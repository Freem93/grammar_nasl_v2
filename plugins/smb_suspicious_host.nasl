#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(23910);
  script_version("$Revision: 1.23 $");
  script_cvs_date("$Date: 2017/02/14 23:15:37 $");

  script_name(english:"Compromised Windows System (hosts File Check)");
  script_summary(english:"Checks the 'hosts' file to determine if the system is compromised.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host may be compromised.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host uses the file 'System32\drivers\etc\hosts' to
fix the name resolution of some sites to localhost or internal
systems. Some viruses or spyware modify this file to prevent antivirus
software or other security software from obtaining updates.

Nessus has found one or more suspicious entries in this file that may
prove the remote host is infected by a malicious program.");
  # https://web.archive.org/web/20041015103959/http://cert.gov/cas/techalerts/TA04-028A.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b5c6c90d");
  script_set_attribute(attribute:"solution", value:
"Remove the suspicious entries from the host file, update your
antivirus software, and remove any malicious software.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_publication_date", value:"2006/12/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Backdoors");
  script_copyright(english:"This script is Copyright (C) 2006-2017 Tenable Network Security, Inc.");

  script_dependencies("hosts_file_settings.nasl", "smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated", "SMB/WindowsVersion");
  script_require_ports(139, 445);
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");

global_var suspicious_hosts;

suspicious_hosts = make_list();
suspicious_hosts[0] = "kaspersky-labs.com";
suspicious_hosts[1] = "grisoft.com";
suspicious_hosts[2] = "symantec.com";
suspicious_hosts[3] = "sophos.com";
suspicious_hosts[4] = "mcafee.com";
suspicious_hosts[5] = "symantecliveupdate.com";
suspicious_hosts[6] = "viruslist.com";
suspicious_hosts[7] = "f-secure.com";
suspicious_hosts[8] = "kaspersky.com";
suspicious_hosts[9] = "avp.com";
suspicious_hosts[10] = "networkassociates.com";
suspicious_hosts[11] = "ca.com";
suspicious_hosts[12] = "my-etrust.com";
suspicious_hosts[13] = "nai.com";
suspicious_hosts[14] = "trendmicro.com";
suspicious_hosts[15] = "microsoft.com";
suspicious_hosts[16] = "virustotal.com";
suspicious_hosts[17] = "avp.ru";
suspicious_hosts[18] = "avp.ch";
suspicious_hosts[19] = "awaps.net";
suspicious_hosts[20] = "google.com";
suspicious_hosts[21] = "bing.com";
suspicious_hosts[22] = "yahoo.com";
suspicious_hosts[23] = "msn.com";

global_var hosts_file_entries;

hosts_file_entries = NULL;

function is_base_host(host, base_host)
{
  local_var host_len, base_host_len, a, diff;

  host = tolower(host);
  base_host = tolower(base_host);

  host_len = strlen(host);
  base_host_len = strlen(base_host);

  a = stridx(host,  base_host);

  diff = (base_host_len + a) - host_len;

  if (((a == 0) ||
      ((a > 0 && host[a-1] == '.')) &&
      diff == 0))
      return TRUE;
}

function get_hostfile_contents()
{
  local_var hosts_content, line, lines, ip_addr, field, fields, item, i, tmp;

  if (!isnull(hosts_file_entries)) return hosts_file_entries;

  hosts_content = get_kb_blob("custom_hosts_contents");

  hosts_file_entries = make_array();

  if (!isnull(hosts_content))
  {
    lines = split(hosts_content, keep:FALSE);
    foreach line ( lines )
    {
      # handle comments. return data with leading and trailing whitespace trimmed
      line = chomp(line);
      item = eregmatch(pattern:"^[\t ]*([^# \t]([^#]*[^# \t])?)?[ \t]*(#.*)?$",
                       string:line);

      if (!isnull(item) && !isnull(item[1]) && item[1] != "")
      {
        tmp = str_replace(find:'\t', replace:' ',  string:item[1]);
        fields = split(tmp, sep:' ', keep:FALSE);
        i=0;
        ip_addr = '';
        foreach field (fields)
        {
          field = str_replace(find:'\t', replace:'', string:field);
          if (field == '') continue;

          if (i == 0 && field !~ "^[0-9a-fA-F.:]+$") break;

          if (i == 0) ip_addr = field;
          else if (i > 0)
          {
            if (isnull(hosts_file_entries[ip_addr]))
              hosts_file_entries[ip_addr] = make_array(field, TRUE);
            else
            {
              if (hosts_file_entries[ip_addr][field] == NULL)
                hosts_file_entries[ip_addr][field] = TRUE;
            }
          }
          i++;
        }
      }
    }
  }
  return hosts_file_entries;
}

function parse_hostfile_line(line)
{
  local_var hf_map, item, field, fields, ip_addr, i, tmp;

  if (isnull(line)) return NULL;
  line = chomp(line);

  item = eregmatch(pattern:"^[\t ]*([^# \t]([^#]*[^# \t])?)?[ \t]*(#.*)?$",
                    string:line);
  if (isnull(item) || isnull(item[1])) return NULL;

  tmp = str_replace(find:'\t', replace:' ',  string:item[1]);
  fields = split(tmp, sep:' ', keep:FALSE);

  i=0;
  ip_addr = '';

  hf_map = make_array();

  foreach field (fields)
  {
    field = str_replace(find:'\t', replace:'', string:field);
    if (field == '') continue;

    if (i == 0 && field !~ "^[0-9a-fA-F.:]+$") break;

    if (i == 0) ip_addr = field;
    else if (i > 0)
    {
      if (isnull(hf_map[ip_addr]))
        hf_map[ip_addr] = make_array(field, TRUE);
      else
      {
        if (hf_map[ip_addr][field] == NULL)
          hf_map[ip_addr][field] = TRUE;
      }
    }
    i++;
  }

  # must parse at least ip and one host name for a valid entry
  if (i <= 1) return NULL;

  return hf_map;
}

function non_custom_suspicious_host(line_map, suspicious_host)
{
  local_var mapping,host, ip_addr, tmp;
  mapping = get_hostfile_contents();
  foreach ip_addr (keys(line_map))
  {
    foreach host (keys(line_map[ip_addr]))
    {
      tmp = tolower(host);

      if (is_base_host(host:host, base_host:suspicious_host))
      {
        # check for custom, overriding entry
        if (mapping[ip_addr][host] != TRUE)
          return TRUE;
      }
    }
  }
  return FALSE;
}

function is_suspicious_entry (line)
{
 local_var len, i, j, pattern, line_map, host;

 line_map = parse_hostfile_line(line:line);
 if (isnull(line_map)) return FALSE;

 foreach host (suspicious_hosts)
 {
   if (
     !ereg(pattern:"^[\s\t]*127.0.0.1[\s\t]*teredo.ipv6.microsoft.com", string:line) &&
      non_custom_suspicious_host(line_map:line_map, suspicious_host:host)
   ) return TRUE;
 }
 return FALSE;
}

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

port = kb_smb_transport();
login = kb_smb_login();
pass = kb_smb_password();
domain = kb_smb_domain();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, "smb_session_init");

path = hotfix_get_systemroot();
if (!path) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:path);
rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, share);
}

file =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\system32\drivers\etc\hosts", string:path);
handle = CreateFile(file: file, desired_access: GENERIC_READ, file_attributes: FILE_ATTRIBUTE_NORMAL, share_mode: FILE_SHARE_READ, create_disposition: OPEN_EXISTING);
if (isnull(handle))
{
 NetUseDel();
 exit(0, "Failed to open '"+(share-'$')+":"+file+"' for reading.");
}

fsize = GetFileSize(handle:handle);
data = NULL;

if (fsize > 0)
  data = ReadFile(handle:handle, length:fsize, offset:0);

CloseFile (handle:handle);
NetUseDel();

if (isnull(data)) exit(0, "Failed to read contents of '"+(share-'$')+":"+file+"'.");

sfiles = NULL;

lines = split(data, sep:'\n', keep:FALSE);
foreach line (lines)
{
 if (is_suspicious_entry(line:line))
   sfiles += string (line, "\n");
}

if (sfiles)
{
  if (report_verbosity > 0)
  {
    if (max_index(split(sfiles)) == 1) entry = "entry";
    else entry = "entries";

    report = '\n' + 'Nessus found the following suspicious ' + entry + ' in the Windows hosts file,' +
             '\n' + (share-'$') + ':' + file + ' : ' +
             '\n' +
             '\n' + sfiles;

    if (!defined_func("nasl_level") || nasl_level() < 5200 || !isnull(get_preference("sc_version"))) security_hole(port:port, extra:report);
    else
    {
      attachments = make_list();
      attachments[0] = make_array();
      attachments[0]["type"] = "text/plain";
      attachments[0]["name"] = "hosts";
      attachments[0]["value"] = data;
      security_report_with_attachments(level:4, port:port, extra:report, attachments:attachments);
    }
  }
  else security_hole(port);
}
else audit(AUDIT_HOST_NOT, 'affected');
