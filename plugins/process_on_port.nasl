#TRUSTED 847fd1cea8be9c6d198c4a92e44d1f667b123e3d06c04cffccbb52b3fcbc3bcd81d6905db2862c102352d1baa47e9f1275a09165c68f042094464e4d3956c5b14fc4148f477969681cbc2036d00da13a3ed5a97e2dbeb41b20a08ed95a4ec4ded43de6350cfa318a7e97e8b5e32b353444186d9fa7f9f1f078e0254d6353fd92bca4eada4e851e5f62470c9444959e43c9373682d86dbe364cf148bca75d05992d5d7068ec6afa04c25c76d76f984404a0dd85ce6065352c4d9bbea7a3496281b116bc68dcd8cdbc6968645312a0d75a3c10c0c95f5df83718b4796b6782f43fc32a0f22ccfdfdf97ef384286852567f4a4f7310e962c428632fdf1807661f97dde680eaf0031f1e34e109c6f6874408f1c8cfdf821428fca4a254767459d199927a56eb826c6b57a1bea872db5879a8cf6544802ad197b61b46ca71ed358249afd2dd9d852dc27bb91a0067da432a16a7821a79ce5cff6f1aeb961438c0b94ae0ca143fcbfbd9764ab30933a4b87ae8e99778d2ee36ccb3b3bc5fb87514fd68f219dd4972f4d008dd6f132f8c691026d449fd6cad989861d763116a57f9b52dcab6e2cf7f8028dc3e28271b9198926218f44d7aeddb9fcfb3cfcad8c4e6d789a22907c1a7e7c68738c3dada4a55ef13c155a743cd202270cc33d01264529802f5805de8551a7687df6badd683de38ee4f5f4b99045ff2446797b9ebfa3c4fb1
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(25221);
 script_version("1.17");
 script_set_attribute(attribute:"plugin_modification_date", value:"2015/06/02");

 script_name(english:"Remote listeners enumeration (Linux / AIX)");
 script_summary(english:"Finds process listening on each port with netstat");

 script_set_attribute(attribute:"synopsis", value:
"Using the supplied credentials, it is possible to identify the
process listening on the remote port.");
 script_set_attribute(attribute:"description", value:
"By logging into the remote host with the supplied credentials, it is
possible to obtain the name of the process listening on the remote port.

Note that this method used by this plugin only works for hosts running
Linux or AIX.");
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2007/05/16");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"agent", value:"unix");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");
 script_family(english:"Service detection");

 script_dependencies("ssh_settings.nasl", "ssh_get_info.nasl");
 script_require_ports("Services/ssh", 22, "nessus/product/agent");
 script_require_keys("Host/uname");

 exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("telnet_func.inc");
include("hostlevel_funcs.inc");

# We may support other protocols here
if ( islocalhost() )
 info_t = INFO_LOCAL;
else
{
 sock_g = ssh_open_connection();
 if (! sock_g) exit(0);
 info_t = INFO_SSH;
}

uname = get_kb_item_or_exit("Host/uname");
if (
  'Linux' >!< uname &&
  'AIX' >!< uname
) audit(AUDIT_HOST_NOT, "Linux / AIX");
# nb: On Solaris, you can do this with a command like:
#
#     pfexec pfiles `ls /proc` 2>/dev/null | egrep '^[0-9]|port:'
#
#     The problem is that pfiles, as its man page warns, can cause a process
#     to stop while its being inspected by the tool, and that is to be
#     avoided in a production environment!


cmdlines = make_array();
localaddrs = make_array();
exes = make_array();
pids = make_array();
prelinked = make_array();
md5s = make_array();

if ("Linux" >< uname)
{
  buf = info_send_cmd(cmd:"prelink -p 2>/dev/null");
  # sanity check
  if('objects found in prelink cache' >< buf)
  {
    foreach entry (split(buf, sep:'\n', keep:FALSE))
    {
      # only interested in binaries, the code below
      # will filter out the libraries
      if(':' >< entry && entry !~ "\[0x[a-zA-Z0-9]+\]")
      {
        item = eregmatch(pattern:"^([^:]+):", string:entry);
        if(!isnull(item)) prelinked[item[1]] = TRUE;
      }
    }
  }

  netstat_cmd = "netstat -anp";
  buf = info_send_cmd(cmd:"LC_ALL=C "+netstat_cmd);
  if (strlen(buf) == 0)
  {
    errmsg = ssh_cmd_error();
    if (errmsg) errmsg ='for the following reason :\n\n' + errmsg + '\n\n';
    else errmsg = 'for an unknown reason. ';
    errmsg = "Failed to run '" + netstat_cmd + "' " + errmsg;
    exit(1, errmsg);
  }
  set_kb_item(name:"Host/netstat_anp", value:buf);

  foreach line (split(buf, keep:FALSE))
  {
    v = eregmatch(string:line, pattern:'^(tcp|udp)[ \t]+[0-9]+[ \t]+[0-9]+[ \t]+([0-9]+\\.[0-9.]+):([0-9]+)[ \t]+([0-9]+\\.[0-9.]+):[0-9*]+[ \t]+(LISTEN[ \t]+)?([0-9]+)/([^ \t].*)?[ \t]*$');
    if (isnull(v))  # Try IPv6 *even* if the target is IPv4
      v = eregmatch(string:line, pattern:'^(tcp|udp)6?[ \t]+[0-9]+[ \t]+[0-9]+[ \t]+([0-9a-f:]+):([0-9]+)[ \t]+([0-9a-f:]+):[0-9*]+[ \t]+(LISTEN[ \t]+)?([0-9]+)/([^ \t].*)?[ \t]*$');
    if (isnull(v)) continue;

    port = int(v[3]);
    if (port < 0 || port > 65535) continue;
    proto = tolower(v[1]);
    if (proto != "tcp" && proto != "udp") continue;

    pid = int(v[6]);
    if (pid > 0)
    {
      exe = info_send_cmd(cmd:"LC_ALL=C "+'readlink \'/proc/'+pid+'/exe\' 2>/dev/null');
      if (strlen(exe) > 0) exe = chomp(exe);

      # check md5sum of process image for further verification if needed  (used in daemons_with_broken_links.nasl)
      if(isnull(md5s[pid]) && ereg(pattern:"^(.+) \(deleted\)$", string:exe))
      {
        exe_md5sum = info_send_cmd(cmd:"LC_ALL=C "+'md5sum \'/proc/'+pid+'/exe\' 2>/dev/null');
        item = eregmatch(pattern:'^([a-zA-Z0-9]{32}) ', string: exe_md5sum);
        if(!isnull(item)) md5s[pid] = item[1];
      }

      cmdline = info_send_cmd(cmd:"LC_ALL=C "+'cat \'/proc/'+pid+'/cmdline\' 2>/dev/null | tr \'\\000\' \' \'');
    }
    else
    {
      exe = cmdline = '';
    }
    if (strlen(exe) == 0) exe = chomp(v[7]);
    if (strlen(exe) == 0) continue;

    k = strcat(proto, '/', port);
    if (exes[k]) continue;

    localaddrs[k] = v[2];
    exes[k] = exe;
    if (pid > 0) pids[k] = pid;
    if (strlen(cmdline) > 0) cmdlines[k] = cmdline;
  }
}
# Suggested by Bernhard Thaler
#
# http://www-01.ibm.com/support/docview.wss?rs=71&uid=swg21264632
else if ("AIX" >< uname)
{
  netstat_cmd = "netstat -Aan";
  buf = info_send_cmd(cmd:"LC_ALL=C "+netstat_cmd);
  if (strlen(buf) == 0)
  {
    errmsg = ssh_cmd_error();
    if (errmsg) errmsg ='for the following reason :\n\n' + errmsg + '\n\n';
    else errmsg = 'for an unknown reason. ';
    errmsg = "Failed to run '" + netstat_cmd + "' " + errmsg;
    exit(1, errmsg);
  }
  set_kb_item(name:"Host/netstat_Aan", value:buf);

  foreach line (split(buf, keep:FALSE))
  {
    v = eregmatch(string:line, pattern:'^(f[a-f0-9]{15})[ \t]+((tcp|udp)[46]?)[ \t]+[0-9]+[ \t]+[0-9]+[ \t]+(\\*|[0-9]+\\.[0-9.]+\\.[0-9]+\\.[0-9]+)\\.([0-9]+)[ \t]+(\\*|[0-9]+\\.[0-9.]+\\.[0-9]+\\.[0-9]+)\\.[0-9*]+([ \t]+LISTEN)?$');
    if (isnull(v)) continue;

    port = int(v[5]);
    if (port < 0 || port > 65535) continue;

    proto = tolower(v[3]);
    if (proto != "tcp" && proto != "udp") continue;

    pcbaddr = v[1];

    exe = cmdline = '';

    cmd = "rmsock " + pcbaddr + " ";
    if (proto == "tcp") cmd += "tcpcb";
    else cmd += "inpcb";

    buf = info_send_cmd(cmd:"LC_ALL=C "+cmd + ' 2>/dev/null');
    if (strlen(buf) > 0)
    {
      buf = chomp(buf);
      v2 = eregmatch(string:buf, pattern:"The socket [^ ]+ is being held by proccess ([0-9]+)[ \t]+\(([^)]+)\)\.");
      if (!isnull(v2))
      {
        pid = int(v2[1]);
        exe = v2[2];

        cmd = "proctree " + pid;
        buf = info_send_cmd(cmd:"LC_ALL=C "+cmd+" 2>/dev/null");
        if (strlen(buf) > 0)
        {
          foreach line (split(buf, keep:FALSE))
          {
            v2 = eregmatch(pattern:'^[ \t]*'+pid+'[ \t]+([^ \t].+)$', string:line);
            if (!isnull(v2)) cmdline = v2[1];
          }
        }
      }
      else
      {
        v2 = eregmatch(string:buf, pattern:"The socket [^ ]+ is being held by Kernel/Kernel Extension\.");
        if (!isnull(v2))
        {
          pid = "n/a";
          exe = "[kernel/kernel extension]";
        }
      }
    }
    if (strlen(exe) == 0) continue;

    k = strcat(proto, '/', port);
    if (exes[k]) continue;

    localaddrs[k] = v[4];
    exes[k] = exe;
    if (pid > 0 || pid == "n/a") pids[k] = pid;
    if (strlen(cmdline) > 0) cmdlines[k] = cmdline;
  }
}

if (max_index(keys(exes)) == 0) exit(0, "The host does not have any listening services.");


found = 0;
ip = get_host_ip();

foreach k (sort(keys(exes)))
{
  v = eregmatch(pattern:"^(.+)/([0-9]+)$", string:k);
  if (isnull(v)) exit(1, "Failed to parse protocol / port info for '"+k+"'.");

  proto = v[1];
  port = v[2];

  exe = exes[k];
  localaddr = localaddrs[k];
  cmdline = cmdlines[k];
  if (strlen(cmdline) == 0) cmdline = "n/a";
  pid = pids[k];

  set_kb_item(name:'Host/Daemons/'+localaddr+'/'+proto+'/'+port, value:exe);

  if (
    (
      TARGET_IS_IPV6 &&
      (localaddr == "::" || localaddr == ip)
    ) ||
    (
      !TARGET_IS_IPV6 &&
      (localaddr == '0.0.0.0' || localaddr == ip || localaddr == "::" || localaddr == "*")
    )
  )
  {
    set_kb_item(name: 'Host/Listeners/'+proto+'/'+port, value:exe);

    found++;

    match = eregmatch(pattern:"^(.+) \(deleted\)$", string:exe);
    if (!isnull(match)) exe = match[1];

    if (exe[0] == '/') lead_slash = '';
    else lead_slash = '/';

    if(!isnull(md5s[pid]))
      replace_kb_item(name: 'Host/DaemonMD5s' + lead_slash + exe, value:md5s[pid]);

    # this is here so we only report on listening pre-linked daemons
    if(prelinked[exe])
    {
      # whitelist
      if(exe =~ "^[0-9A-Za-z_\-./]+$")
        buf = info_send_cmd(cmd:"prelink -y " + exe + " | md5sum");

      item = eregmatch(pattern:'^([a-zA-Z0-9]{32}) ', string: buf);
      if(!isnull(item))
        replace_kb_item(name: 'Host/PrelinkedDaemons' + lead_slash + exe, value:item[1]);
      else
        replace_kb_item(name: 'Host/PrelinkedDaemons' + lead_slash + exe, value:'md5_unknown');

    }
    report = '\n  Process id   : ' + pid +
             '\n  Executable   : ' + exe;
    if (strlen(cmdline) > 0) report += '\n  Command line : ' + cmdline;
    report += '\n';
    if (COMMAND_LINE) report = '\n  Port         : ' + port + ' (' + proto + ')' + report;

    if (report_verbosity > 0) security_note(port:port, proto:proto, extra:report);
    else security_note(port:port, proto:proto);
  }
}
if (found) set_kb_item(name:"Host/Listeners/Check", value:netstat_cmd);
