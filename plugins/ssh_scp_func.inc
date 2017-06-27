#TRUSTED 07025ec11b48495e9a411407c0bf380e16823340dcb616ccef92cdb4ec1559ed7829b5c46e7c79d66d417fe20d0cd59451bbf67345097b23fd78102666e9f894048f89e72d3ea18e6491540b80765a2ed2b361a3d4cdbaa1647e797682eefef552891d86dec9c0e2276753996f6e563d84f167e3909e0607e17977ca5cb24f3d713496e978d92147dd7d1a0b0a1f2e26cfd48837f289389ee4aa57fe7a8c7d651c66584220c784934cdb6078df7ff43cb91fd0596d9c95ba2f9d077f1bf1cdead659e9d48dc4281fb0940df9cca754361fe981c38302faa268d4c7d8c62c784a3b5c241632938cadc26004e4664171389c529b07b9d7ae344e5349dbb61755e593e4bbccff07469388b8db44bc65c2ec1b9f230cbde78b36cb6f885c6e3d7a1cb3c50ccb07cb3c52bd0443835ae4550e7f2086080703372adfbfedb6c0c96ba7be3a21db807f4b16fabcbaba5ffa3d5bbb24a2c43a390988f405628a3aa4d9122ef6f5a2d08a32073274283ff48c33e22e3d7315acaef58a3d2062eb58fe7f535f94523b1c6deb44ccdf90108ad0e6abb7c32a9d4ee22034106206a5a027c346ab2dcd0609cf9bd3b269319b21f35f4225449823b3a661f3f1a730f642150c16a2ff9d861ca514d47479afd0ba3c20cf9d5a90ec921a7fe3b201c3e77004b97a27187b538f37687216e0c672d8a367d89466130c8bb5abe4bd283bd3f8d156e4
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# Revision 1.1
#

global_var ssh_scp_state;
global_var SSH_SCP_NEW, SSH_SCP_CHANNEL_OPEN, SSH_SCP_READ_INITED;

SSH_SCP_NEW = 0;
SSH_SCP_CHANNEL_OPEN = 1;
SSH_SCP_READ_INITED = 2;

ssh_scp_state = SSH_SCP_NEW;

##
# Initializes and SCP session over SSH
# @returns TRUE on success, FALSE on failure
##
function ssh_scp_init()
{
  local_var ret;
  if(ssh_scp_state != SSH_SCP_NEW)
    set_ssh_error(msg:"ssh_scp_init called under invalid state.");

  ret = ssh_open_channel();
  if (ret != 0)
  {
    set_ssh_error(msg:"Nessus failed to open a new SSH channel.");
    return FALSE;
  }
  ssh_scp_state = SSH_SCP_CHANNEL_OPEN;
  return TRUE;
}

##
# Pulls remote files using SCP over SSH
# @param location file(s) location
# @param recursive TRUE if recursive, FALSE if not
# @returns NULL on error or array with results
##
function ssh_scp_pull_file(location, recursive)
{
  local_var scp_command;

  if (location !~ '^(( *[*A-Za-z0-9_./\\[\\]][*A-Za-z0-9_.\\-/\\[\\]]*)*|'+
                  '(\'[*A-Za-z0-9_.\\-/\\[\\] ]*\')|'+
                  '("[*A-Za-z0-9_.\\-/\\[\\] ]*"))$')
  {
    set_ssh_error(msg:"location path contains unsafe characters.");
    return NULL;
  }

  if(isnull(recursive)) recursive = FALSE;

  if(ssh_scp_state != SSH_SCP_CHANNEL_OPEN)
    set_ssh_error(msg:"ssh_scp_pull_file called under invalid state.");

  scp_command = "scp -f ";
  if(recursive) scp_command += "-r ";

  scp_command += location;

  if(!ssh_request_channel(s:"exec", extra:putstring(buffer:scp_command)))
    return NULL;

  return _ssh_scp_recv_files();
}

function _ssh_scp_recv_files ()
{
  local_var payload, tempbuf, item, cur_file, results, dir_path, dir_level, dir_path_history, tmp_len,
            directory, sub_path;
  payload = recv_ssh_packet();
  results = make_array();
  cur_file = NULL;
  dir_path = '';
  dir_path_history = make_list();
  dir_level = 0;

  while(ord(payload[0]) != SSH2_MSG_CHANNEL_CLOSE && ord(payload[0]) != 0 && strlen(payload) > 0)
  {
    if (ord(payload[0]) == SSH2_MSG_CHANNEL_WINDOW_ADJUST)
    {
      payload = ntol(buffer:payload, begin:5);
      r_window_size += payload;
    }
    else if (ord(payload[0]) == SSH2_MSG_CHANNEL_DATA || ord(payload[0]) == SSH2_MSG_CHANNEL_EXTENDED_DATA)
    {
      tempbuf = getstring(buffer:payload, pos:5);
      if(update_window_size(size:strlen(tempbuf)) != 0) break;
      if(!isnull(cur_file))
      {
        tmp_len = strlen(tempbuf);
        if((strlen(cur_file['contents']) + tmp_len) > cur_file['size'])
        {
          cur_file['contents'] += substr(tempbuf, 0, strlen(tempbuf) - 2);
          results[cur_file['path'] + '/' + cur_file['name']] = cur_file;
          cur_file = NULL;
        }
        else cur_file['contents'] += tempbuf;
      }
      else
      {
        if(tempbuf[0] == "C")
        {
          item = eregmatch(pattern:"^C(\d{4}) (\d+) ([^\n]+)\n$", string:tempbuf);
          if(isnull(item))
          {
            set_ssh_error(msg:"SCP protocol parse error.");
            return NULL;
          }
          cur_file = make_array(
            'name', item[3],
            'type', 'C',
            'size', int(item[2]),
            'perm', item[1],
            'contents', '',
            'rel_path', dir_path
          );
        }
        else if(tempbuf[0] == 'D')
        {
          item = eregmatch(pattern:"^D(\d{4}) (\d+) ([^\n]+)\n$", string:tempbuf);
          if(isnull(item))
          {
            set_ssh_error(msg:"SCP protocol parse error.");
            return NULL;
          }
 
          directory = make_array(
            'name', item[3],
            'type', 'D',
            'size', int(item[2]),
            'perm', item[1],
            'rel_path', dir_path
          );

          if(dir_path == '')
            dir_path = item[3];
          else
            dir_path += '/' + item[3];

          results[dir_path] = directory;

          dir_level++;
          dir_path_history = make_list(dir_path_history, item[3]);
        }
        else if(tempbuf[0] == 'E')
        {
          sub_path = "/" + dir_path_history[dir_level - 1];
          dir_path -= sub_path;
          dir_level--;
        }
        else if(tempbuf[0] == '\x01')
        {
          set_ssh_error(msg:'SCP warning : ' + tempbuf);
          return NULL;
        }
        else if(tempbuf[0] == '\x02')
        {
          set_ssh_error(msg:'SCP error : ' + tempbuf);
          return NULL;
        }
        else
        {
          set_ssh_error(msg:'unhandled SCP message : ' + tempbuf);
          return NULL;
        }
      }
    }

    payload = raw_int32(i:remote_channel) + putstring(buffer:'\0');
    send_ssh_packet(payload:payload, code:raw_int8(i:SSH2_MSG_CHANNEL_DATA));

    payload = recv_ssh_packet();
  }
  return make_nested_list(results);
}
