#TRUSTED 3c5c7dbc128078f0e18ab725ce2f226c4a38ae3ca4ad4f60382fb27ed5633f56d3f86dd255d0797a0551a064ae66828a5e3c5f588230da61c110609996593b551f661a9ccaf20832315e865ff5290063c8e53a415edeeef3e699cf70c466536f4ab04fc0095b07e19982cf1084230fed90649365d303682cab2e47f7d16366c769666e74d951260098ad420a520d7f3d80ca04771aabca4b6c5ed984dadc4463c7f17f4504ae3ce4b1a406370e76d7cdc290eb27e570428c31d11849274d82d9ba9e417ad23df01affd9aa9f049d2e2301ce3f61d1e1994cd1e74fd86a79d3fbe6433e2f127a6cf9fdf10d34364619c3678cd1a9f564e29c5117dd3fb9ac0d757227724ff0c1a546c9485de35b202f28fccfa33fc5fd92e6d182a0a65e58455886b1ae7cc1901a1534afb293abded1c9f5d0e4be0c459d339b8b7e2bc90782736501cdd32cc28e63ac551f359b5b81fd5b72d3df84ca2c6fa254da1c59d77c73db4537e12d954a6f6ab0f01fa2fd6f886345457dd249f153ca11ca6dacf7d27140ee3114c9ff2353ccddc700cbc82ef04ca49f2dfc560271fc5f5570717e20d833bf461219f6aef04c423954e5d58f1dc9e7f12131a0178e9bbe84e34ac83e8656e0c646d63e726fc0c0d3c3456fcdf6553b1760549dbadcff2fd43a83d8b9e19256b054b576301be05d18f393961f4e93f00d42928557cee97cd121857e300b
#
# (C) Tenable Network Security, Inc.
#


if (!defined_func("bn_random")) exit(0);


include("compat.inc");


if (description)
{
  script_id(50681);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

  script_cve_id("CVE-2010-4011");
  script_bugtraq_id(44874);
  script_osvdb_id(69260);

  script_name(english:"Mac OS X Server v10.6.5 (10H575)");
  script_summary(english:"Checks ProductBuildVersion in /System/Library/CoreServices/ServerVersion.plist");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has an application that may be affected by an
information disclosure vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"A memory aliasing issue in Dovecot's handling of user names in Mac OS
X Server v10.6.5 may result in a user receiving mail intended for
other users. 

Note that this vulnerability arises only on Mac OS X Server systems
when Dovecot is configured as a mail server."
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://support.apple.com/kb/HT4452"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://lists.apple.com/archives/security-announce/2010/Nov/msg00001.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade to Mac OS X Server v10.6.5 (10H575) or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/11/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/11/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2010-2017 Tenable Network Security, Inc.");

  script_dependencies("macosx_server_services.nasl");
  script_require_keys("Host/uname", "MacOSX/Server/Version");

  exit(0);
}


include("ssh_func.inc");
include("macosx_func.inc");


function exec(cmd)
{
  local_var ret, buf;

  if (islocalhost())
    buf = pread(cmd:"/bin/bash", argv:make_list("bash", "-c", cmd));
  else
  {
    ret = ssh_open_connection();
    if (!ret) exit(1, "ssh_open_connection() failed.");
    buf = ssh_cmd(cmd:cmd);
    ssh_close_connection();
  }

  return buf;
}


uname = get_kb_item("Host/uname");
if (!uname) exit(0, "The 'Host/uname' KB item is missing.");

# Mac OS X 10.6 only.
if (!egrep(pattern:"Darwin.* 10\.", string:uname)) exit(0, "The remote Mac is not running Mac OS X 10.6.");


version = get_kb_item("MacOSX/Server/Version");
if (!version) exit(1, "Failed to retrieve the Mac OS X Server version.");
if ("Server 10.6" >!< version) exit(0, "The host is running "+version+" and thus not affected.");


# And check it.
#
# nb: Apple says only 10H574 is affected.
if ("(10H574)" >< version)
{
  # Unless we're paranoid, make sure Dovecot is being used for mail.
  gs_opt = get_kb_item("global_settings/report_paranoia");
  if (gs_opt && gs_opt != 'Paranoid')
  {
    status = get_kb_item("MacOSX/Server/mail/Status");
    if (!status) exit(1, "Failed to retrieve the status of the 'mail' service.");

    if ("RUNNING" >!< status)
      exit(0, "The mail service is not running, and thus the host is not affected.");

    cmd = 'serveradmin settings mail:postfix:mailbox_transport';
    buf = exec(cmd:cmd);
    if (!buf) exit(1, "Failed to run '"+cmd+"'.");

    if (!eregmatch(pattern:'mailbox_transport *= *"dovecot"', string:buf)) 
      exit(0, "The mail service does not use Dovecot, and thus the host is not affected.");

    report_trailer = '';
  }
  else report_trailer = 
    '\n' +
    'Note, though, that Nessus did not check whether the mail service is\n' +
    'running or Dovecot is in use because of the Report Paranoia setting in\n' +
    'effect when this scan was run.\n';

  gs_opt = get_kb_item("global_settings/report_verbosity");
  if (gs_opt && gs_opt != 'Quiet')
  {
    version = strstr(version, "Server ") - "Server ";

    report = 
      '\n  Installed system version : ' + version + 
      '\n  Fixed system version     : 10.6.5 (10H575)\n';
    if (report_trailer) report += report_trailer;

    security_warning(port:0, extra:report);
  }
  else security_warning(0);

  exit(0);
}
else exit(0, "The remote host is not affected since Mac OS X Server build version "+version+" is installed.");
