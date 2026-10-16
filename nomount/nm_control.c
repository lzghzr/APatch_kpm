/* SPDX-License-Identifier: GPL-2.0-only */
/* Commands use the pinned NoMount wire protocol and the module's topology engine. */
static void nm_control_error(struct nm_payload* payload, int rc) {
  if (rc && !payload->status)
    payload->status = rc;
}

static int nm_control_rules(struct nm_payload* payload, bool add) {
  unsigned int offset = payload->arg1, end = payload->data_size;
  if (end > sizeof(payload->buffer) || offset > end)
    return -EINVAL;
  struct nm_topology_updates updates = {0};
  if (!add)
    nm_management_lock();
  while (offset < end) {
    unsigned int header = add ? sizeof(struct nm_rule_hdr) : sizeof(struct nm_del_hdr);
    if (end - offset < header) {
      nm_control_error(payload, -EINVAL);
      break;
    }
    struct nm_rule_hdr rule_header = {0};
    struct nm_del_hdr del_header;
    if (add)
      memcpy(&rule_header, payload->buffer + offset, header);
    else {
      memcpy(&del_header, payload->buffer + offset, header);
      rule_header.uid = del_header.uid;
      rule_header.v_len = del_header.v_len;
    }
    unsigned int names = (unsigned int)rule_header.v_len + rule_header.r_len;
    if (!rule_header.v_len || rule_header.v_len >= 4096 || rule_header.r_len >= 4096 || names > end - offset - header) {
      nm_control_error(payload, -EINVAL);
      break;
    }
    const char* path = payload->buffer + offset + header;
    int rc;
    if (add) {
      // backing解析可进入VFS回调，必须在管理锁外完成。
      struct nomount_rule* rule =
          nm_alloc_rule(path + rule_header.v_len, rule_header.r_len, rule_header.flags, rule_header.uid);
      if (IS_ERR(rule))
        rc = PTR_ERR(rule);
      else {
        nm_management_lock();
        rc = nm_topology_add_locked(path, rule_header.v_len, rule, &updates);
        nm_management_unlock();
        if (rc)
          nm_rule_put(rule);
      }
    } else
      rc = nm_topology_remove_locked(path, rule_header.v_len, rule_header.uid, &updates);
    nm_control_error(payload, rc);
    offset += header + names;
  }
  if (!add) {
    nm_management_unlock();
    if (!updates.rules.rules && !updates.leaves && !payload->status)
      payload->status = -ENOENT;
  }
  payload->arg1 = offset;
  nm_finish_topology_updates(&updates);
  return payload->status;
}

static int nm_control_list(struct nm_payload* payload) {
  u32 index = 0, start = payload->arg1;
  unsigned int used = 0;
  int rc = 0;
  nm_management_lock();
  for (struct nm_topology_leaf* entry = nm_topology_leaves; entry; entry = entry->next) {
    if (entry->automatic)
      continue;
    struct nm_rule_array* array = nm_rules_load(entry->leaf->rules);
    if (!array)
      continue;
    for (u32 i = 0; i < array->count; i++) {
      struct nomount_rule* rule = array->rules[i];
      if (rule->inherit_backing)
        continue;  // 此保留目录由子规则重建，不能序列化成显式纯目录。
      if (index == (u32)-1) {
        rc = -EOVERFLOW;
        goto done;
      }
      if (index < start) {
        index++;
        continue;
      }
      unsigned int bytes = sizeof(struct nm_rule_hdr) + entry->leaf->v_len + rule->r_len;
      if (bytes > sizeof(payload->buffer) - used) {
        if (!used)
          rc = -EOVERFLOW;
        goto done;
      }
      struct nm_rule_hdr header = {
          .flags = rule->flags, .uid = rule->target_uid, .v_len = entry->leaf->v_len, .r_len = rule->r_len};
      memcpy(payload->buffer + used, &header, sizeof(header));
      used += sizeof(header);
      memcpy(payload->buffer + used, entry->leaf->paths, header.v_len);
      used += header.v_len;
      memcpy(payload->buffer + used, rule->paths, header.r_len);
      used += header.r_len;
      index++;
    }
  }
done:
  nm_management_unlock();
  payload->data_size = used;
  payload->arg1 = index;
  return rc;
}

static int nm_execute_payload(struct nm_payload* payload) {
  if (!payload || payload->magic != NOMOUNT_MAGIC_SIG)
    return -EINVAL;
  payload->status = 0;
  if (!nm_management_mutex || !nm_topology_ready) {
    payload->status = -ENODEV;
    return -ENODEV;
  }
  int rc = 0;
  switch (payload->cmd) {
    case NM_CMD_GET_VERSION:
      payload->data_size = sizeof(NM_KPM_VERSION) - 1;
      memcpy(payload->buffer, NM_KPM_VERSION, payload->data_size);
      break;
    case NM_CMD_ADD_RULE:
    case NM_CMD_DEL_RULE:
      rc = nm_control_rules(payload, payload->cmd == NM_CMD_ADD_RULE);
      break;
    case NM_CMD_GET_LIST:
      rc = nm_control_list(payload);
      break;
    case NM_CMD_GET_UIDS:
      nm_uid_list(payload);
      break;
    case NM_CMD_ADD_UID:
    case NM_CMD_DEL_UID:
      nm_management_lock();
      rc = payload->cmd == NM_CMD_ADD_UID ? nm_uid_add(payload->target_uid) : nm_uid_del(payload->target_uid);
      nm_management_unlock();
      break;
    case NM_CMD_BLOCK_ISOLATED_UIDS:
      __atomic_store_n(&nm_block_isolated_uids, payload->arg1 != 0, __ATOMIC_RELAXED);
      break;
    case NM_CMD_GET_ISOLATED_STATE:
      payload->buffer[0] = __atomic_load_n(&nm_block_isolated_uids, __ATOMIC_RELAXED) ? '1' : '0';
      payload->buffer[1] = '\n';
      payload->data_size = 2;
      break;
    case NM_CMD_CLEAR_ALL:
    case NM_CMD_CLEAR_RULES:
    case NM_CMD_CLEAR_UIDS: {
      struct nm_topology_updates updates = {0};
      nm_management_lock();
      if (payload->cmd != NM_CMD_CLEAR_UIDS)
        rc = nm_topology_clear_locked(&updates);
      if (payload->cmd != NM_CMD_CLEAR_RULES)
        nm_uid_clear();
      nm_management_unlock();
      nm_finish_topology_updates(&updates);
      break;
    }
    default:
      rc = -EINVAL;
  }
  nm_control_error(payload, rc);
  return payload->status;
}
