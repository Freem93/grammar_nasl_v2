#TRUSTED 7e3c4adb869557ddb0916e093e57916a19a24f1637bb5b7fee9687ed27745750fec3c604356d52fa289747bb45e6340b81c85f358e0fd2e081ca8538d78aa794d30874e1a9700bd0d07e02053eca6e1bd38a581a31e0d4abf29ac83dc4e7d65ade672c8981aa00ca1eca98317e94001b435cc937554b474484132ff28de56ac9162dff1bc5f2eca61feaf47c476ed2e0ecda7bdb3ac7f66dc43fb8aef05c557faecc4f79d5976fac0430a96dd25e04818bcf273857e47e5d4121b933c2cd6f7dd79e0a34b50f2e6f8adb914395908798c8effcf44b3fc5121e0237d65a0ac94c6c9e4c4550a78a5fc25fd82a4ff52ae923560375594e9bbf534a7000955651fef3e96674e75e30fbf94c170276ad6dc168d3d6f625d9c45f494b908e114d17395d478a4d28f8ee2d132a40963e2bd7a10c3e409805a585611a6650f14098639ca3e1682164cd77e4dc2e5a72777ee02cc402121a48e156d12ecd8e2aa70dc154e967ef10a49e5cebc484eea4d610e93279c79bde06bb8aa04b0be3e982246f45f7e9a230533026488c9d25d201ec7528ed8f92a2cbd2f5877c91756f7cfb2a13b05bda5282ff7205b9a7ff9ea58f1859da20eb454743e0bcc65a602155670f811c29858026b41efb186886949c80c5d2419e0acc2b481843ed73c8f4fbc6f6e6a9b28299e1f555a1f9b846761752dec4814892e8fe5f43bb1493021e3a930d56
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(32320);
 script_version("1.17");
 script_set_attribute(attribute:"plugin_modification_date", value:"2016/11/17");

 script_cve_id("CVE-2008-0166");
 script_bugtraq_id(29179);
 script_osvdb_id(45029, 45503);
 script_xref(name:"CERT", value:"925211");
 script_xref(name:"EDB-ID", value:"5720");

 script_name(english:"Weak Debian OpenSSH Keys in ~/.ssh/authorized_keys");
 script_summary(english:"Checks for the remote SSH public keys.");

 script_set_attribute(attribute:"synopsis", value:
"The remote SSH host is set up to accept authentication with weak
Debian SSH keys.");
 script_set_attribute(attribute:"description", value:
"The remote host has one or more ~/.ssh/authorized_keys files
containing weak SSH public keys generated on a Debian or Ubuntu
system.

The problem is due to a Debian packager removing nearly all sources of
entropy in the remote version of OpenSSL.

This problem does not only affect Debian since any user uploading a
weak SSH key into the ~/.ssh/authorized_keys file will compromise the
security of the remote system.

An attacker could try a brute-force attack against the remote host and
logon using these weak keys.");
 script_set_attribute(attribute:"solution", value:
"Remove all the offending entries from ~/.ssh/authorized_keys.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_cwe_id(310);

 script_set_attribute(attribute:"vuln_publication_date", value:"2008/05/14");
 script_set_attribute(attribute:"plugin_publication_date", value:"2008/05/15");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"agent", value:"unix");
 script_set_attribute(attribute:"in_the_news", value:"true");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Gain a shell remotely");

 script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

 script_dependencie("ssh_detect.nasl", "ssh_get_info.nasl");
 script_require_keys("Host/local_checks_enabled");
 script_require_ports("Services/ssh", 22);

 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("byte_func.inc");
include("ssh_func.inc");
include("telnet_func.inc");
include("hostlevel_funcs.inc");
include("audit.inc");

get_kb_item_or_exit("Host/local_checks_enabled");

SSH_RSA = 0;
SSH_DSS = 1;

function file_read_dword(fd)
{
  local_var dword;

  dword = file_read(fp:fd, length:4);
  dword = getdword(blob:dword, pos:0);

  return dword;
}

function find_hash_list(type, first, second)
{
  local_var list, fd, i, j, main_index, sec_index, c, offset, length, len, pos, file, tmp_list;

  if (type == SSH_RSA)
    file = "blacklist_rsa.inc";
  else if (type == SSH_DSS)
    file = "blacklist_dss.inc";

  if ( ! file_stat(file) ) return NULL;

  fd = file_open(name:file, mode:"r");
  if (!fd) return NULL;

  main_index = file_read_dword(fd:fd);

  for (i=0; i<main_index; i++)
  {
    c = file_read(fp:fd, length:1);
    offset = file_read_dword(fd:fd);
    length = file_read_dword(fd:fd);

    if (c == first)
    {
      file_seek(fp:fd, offset:offset);
      sec_index = file_read_dword(fd:fd);

      for (j=0; j<sec_index; j++)
      {
        c = file_read(fp:fd, length:1);
        offset = file_read_dword(fd:fd);
        length = file_read_dword(fd:fd);

        if (c == second)
        {
          file_seek(fp:fd, offset:offset);
          tmp_list = file_read(fp:fd, length:length);

          len = strlen(tmp_list);
          pos = 0;

          for (j=0; j<len; j+=10)
            list[pos++] = substr(tmp_list, j, j+9);
          break;
         }
      }
      break;
    }
  }

  file_close(fd);

  return list;
}

function is_vulnerable_fingerprint(type, fp)
{
  local_var list, i, len;

  list = find_hash_list(type:type, first:fp[0], second:fp[1]);
  if (isnull(list))
    return FALSE;

  len = max_index(list);

  for (i=0; i<len; i++)
    if (list[i] == fp)
      return TRUE;

  return FALSE;
}

function wrapline()
{
  local_var ret;
  local_var i, l, j;
  local_var str;
  str = _FCT_ANON_ARGS[0];
  l = strlen(str);
  for ( i = 0 ; i < l; i += 72 )
  {
    for ( j = 0 ; j < 72 ; j ++ )
    {
       ret += str[i+j];
       if ( i + j + 1 >= l ) break;
    }
    ret += '\n';
  }
  return ret;
}

function get_key()
{
  local_var pub, public, pubtab, num, i, line,blobpub,fingerprint,ret ;
  local_var file_array, keyfile, filename, home, text;
  local_var pub_array;
  local_var report;
  local_var home_report;
  local_var flag;
  local_var path;
  local_var file;

  text = _FCT_ANON_ARGS[0];
  if ( ! text ) return NULL;
  home_report = NULL;
  home = split(text, keep:FALSE);
  home = home[0];
  if(home[strlen(home)-1] == "/") home += ".ssh/";
  else home += "/.ssh/";
  file_array = split(text, sep:"## ", keep:FALSE);
  foreach keyfile (file_array)
  {
    line = 0;
    flag = 0;
    pub_array = split(keyfile, keep:FALSE);
    filename = pub_array[0];
    report = '\n'+"In file " + home + filename + ':\n';
    foreach pub ( pub_array )
    {
      if ("# NOT FOUND" >< pub || "id_dsa.pub" >< pub || "id_rsa.pub" >< pub || "authorized_keys" >< pub || "### FINISHED" >< pub)
        continue;

      line ++;
      if ( pub !~ "ssh-[rd]s[sa]" ) continue;
      public = ereg_replace(pattern:".*ssh-[rd]s[sa] ([A-Za-z0-9+/=]+) .*$", string:pub, replace:"\1");
      if ( public == pub ) continue;

      blobpub = base64decode(str:public);
      fingerprint = substr(MD5(blobpub), 6, 15);
      if ("ssh-rsa" >< blobpub)
      {
        ret = is_vulnerable_fingerprint(type:SSH_RSA, fp:fingerprint);
        if (ret)
        {
          report += "line " + line + ':\n' + wrapline(pub);
          flag ++;
        }
      }
      else
      {
        ret = is_vulnerable_fingerprint(type:SSH_DSS, fp:fingerprint);
        if (ret)
        {
          report += "line " + line + ':\n' + wrapline(pub);
          flag ++;
        }
      }
    }
    if( flag > 0 ) home_report += report;
  }

  if ( empty_or_null(home_report) ) return NULL;
  return home_report;
}

# Decide transport for testing
if (islocalhost())
{
  if ( ! defined_func("pread") ) exit(1, "'pread()' is not defined.");
  info_t = INFO_LOCAL;
}
else
{
  sock_g = ssh_open_connection();
  if (!sock_g) audit(AUDIT_FN_FAIL, 'ssh_open_connection');
  info_t = INFO_SSH;
}

cmd = info_send_cmd(cmd:'cat /etc/passwd | cut -d: -f6 | grep -v "[;&|'+"\"+'`$]" | while read h; do [ -d "$h/.ssh" ] && echo "### HOME: $h" && (for f in id_rsa.pub id_dsa.pub authorized_keys; do echo "## $f"; cat "$h/.ssh/$f" 2>/dev/null || echo "# NOT FOUND"; done); done; echo "### FINISHED"');
if ( ! cmd || "## id_rsa.pub" >!< cmd) exit(0, "Failed to get the contents of the /etc/passwd file.");
homes = make_list();

foreach home ( split(cmd, sep:"### HOME: ", keep:FALSE) )
{
  homefold = split(home);
  homefold = homefold[0];
  if(homes[homefold]) continue;
  else homes[homefold] = home;
}

foreach home ( homes )
{
  report += get_key(home);
}

if (report)
{
  security_report_v4(severity:SECURITY_HOLE, port:0, extra:report);
}
else
  audit(AUDIT_HOST_NOT,"affected");
