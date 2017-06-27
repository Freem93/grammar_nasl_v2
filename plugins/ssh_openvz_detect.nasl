#TRUSTED b26cb157f690dfc6f1475099857d3f4de1a6cec7ce08bcbcf5232599e8b6c67bf8f886d7247f9a88a2ef9813e415a4214303da54770f5c45d035e6ee371480e16ea1776b784ae12238db93156d5a725d5cabcc923518da8002aee298acc80e92c14cf8bbce07eb90c895f6e278a5dcd08d0e24646b16e29d8cc9a1e20159fb83a85f7fa90d4db576cabbdcdb44cfbceae44cbe64b21619f048e66a47c10fde494d5254cf789fd732906030f017fbef68ba8d931e1228af576f2f840759c54d3a3f4b41f274c6d5c27126d1b44410ee5656e373bcf79ac91da37e2136d774d1bba5a65144675a6ea82b8b2ab84421f1b09567440c5827e099c972a8cd87e82997913ac4c87ed5f7eeb05860929db5534a0dbf3ec9cdde6c6e671135cb4eb1cde58e6b8d884a8db9871d761d6d52a87a386c05be5507c38cd07b789cb1eab31950e2fe8128d7b4fa915281d40de6da2936a710d073e83b8bafd3eef809879fcf9679f62459a37167e53bdcb7fdb82133543a7f3d8f6b6706e74b1eb9f4391254f552f1caf233887f0d32c3d83c807790fdfd560bbc7ec3184fdbb6f7f30c532fd18b652756b23248b06767406ed76fc655474600d3a128a1eabca362e75d8a963e08e8a0f52801880af6ce31f61c88e2fddfca02981eef8fbb7e0ae5fe178b65184aaa9603192e2ce35b579996e884741d5e00a863751e342603dfb9d2be88f245
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(51092);
 script_version("1.3");
 script_set_attribute(attribute:"plugin_modification_date", value:"2011/06/07");

 script_name(english:"OpenVZ Guest Detection");
 script_summary(english:"Determines if the remote OS is running in an OpenVZ container");

 script_set_attribute(attribute:"synopsis", value:
"The remote host seems to be an OpenVZ virtual machine." );
 script_set_attribute(attribute:"description", value:
"/proc/user_beancounters could be read.  This file provides
information to the guest operating system in OpenVZ containers." );
 script_set_attribute(attribute:"see_also", value: "http://wiki.openvz.org/Proc/user_beancounters");
 script_set_attribute(attribute:"see_also", value: "http://en.wikipedia.org/wiki/OpenVZ");
 script_set_attribute(attribute:"solution", value:
"Ensure that the host's configuration is in agreement with your
organization's security policy." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value:"2010/12/09");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2010-2011 Tenable Network Security, Inc.");
 script_family(english:"Misc.");
 script_dependencies("ssh_settings.nasl", "ssh_get_info.nasl");
 exit(0);
}

include("ssh_func.inc");
include("telnet_func.inc");
include("hostlevel_funcs.inc");

if ( ! get_kb_item('HostLevelChecks/proto' ) ) exit(0, "No credentials to log into the remote host");


# We may support other protocols here
if ( islocalhost() )
{
 if ( ! defined_func("pread") ) exit(1, "'pread()' is not defined.");
 info_t = INFO_LOCAL;
}
else
{
 sock_g = ssh_open_connection();
 if (! sock_g) exit(1, "ssh_open_connection() failed.");
 info_t = INFO_SSH;
}

cmd = 'LC_ALL=C cat /proc/user_beancounters';
buf = info_send_cmd(cmd: cmd);
if ('uid' >< buf && 'resource' >< buf && 'held' >< buf && 'maxheld' >< buf &&
    egrep(string: buf, pattern: 
 '^[ \t]+uid[ \t]+resource[ \t]+held[ \t]+maxheld[ \t]+barrier[ \t]'))
{
  if ( strlen(buf) < 8192 &&
       "Verbose" >< get_kb_item("global_settings/report_verbosity") )
    security_note(port: 0, extra: '\n/proc/user_beancounters contains :\n\n' + buf);
  else
    security_note(port: 0);  
  exit(0);
}
else exit(0, "The host does not appear to be an OpenVZ Guest.");
