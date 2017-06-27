#TRUSTED 81af3864b2966618e6f76485024e5b9be49c99d769403ae39d318e69eee5d54db720788e6167b87f277fca185b51293e9b8f0d9637b88691ee3ea469d950a582520bd046dce9c60013fcf15f2505db289ff9700f5d016d86cef92c7226dddcac009b5ddacc62c5b139367f97ce6bf0c8b14f0abff14ecd39c16df9d42d1930785aa7f523ff37549c75ac85e849cc76a30ee22a01d15581b0bb977e3504ff3aed48a3f2e9a05893aa80d003e6073c45f9f21f3ee218803f45af742bd4f38de8df29984cada6abd763ea7265140f21f9682b9ef67ae9cd28028da39f31cd28dd2738c97204cec22dd8706a2c3dd86d6ab904ee0b21569d39bb5c990fe0f434a4e626798a8bd7d5a2b4644ebb767a1be9e4b3f73497451c38abd92c5219bac920c05067126b0a6a47b19fbfa6cc657d6990252daba838ed9223c3b3c89e9590808c788b5f2966c92aebbebfa5b1ad3362cac58f9a7f81ea351dd885e44c0a94bd0512fc3dad5dd510b5d02c71211e154361daacd550a62c73d50ac3fed957caa8708a336c4cf54028f2f58fc469a8f4bc88de5e46fa44437198325ecbfb9e84581b961a3e03d3df943a4bb29066909dddda58196d4eae6280da4a4ec68a6e057ba8ddcb5b9768cdb6686c17de365f5ee460a6de6eec944ae9abfa2007a671460de8b8dc0bc3af9c3689421b9b1f05e892a7ee0f451f39268d1f8e496cc20893117e
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69922);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2013/09/17");

  script_name(english:"Cisco Firewall Services Module (FWSM) Version");
  script_summary(english:"Obtains the version of the remote FWSM");

  script_set_attribute(attribute:"synopsis", value:
"It is possible to obtain the FWSM version of the remote Cisco
device.");
  script_set_attribute(attribute:"description", value:
"The remote host has a Cisco Firewall Services Module (FWSM). 

It is possible to read the FWSM version by connecting to the switch
using SSH.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:firewall_services_module");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");
  script_require_ports("Services/ssh", 22);
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("hostlevel_funcs.inc");

##
# Saves the provided FWSM version number in the KB, generates plugin output,
# and exits.
#
# @anonparam ver FWSM version number
# @anonparam source protocol used to obtain the version
# @return NULL if 'ver' is NULL,
#         otherwise this function exits before it returns
##
function report_and_exit(ver, source)
{
  local_var report;

  set_kb_item(name:"Host/Cisco/FWSM/Version", value:ver);

  replace_kb_item(name:"Host/Cisco/FWSM", value:TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\n  Source  : ' + source +
      '\n  Version : ' + ver;
    report += '\n';
    security_note(port:0, extra:report);
  }
  else security_note(0);

  exit(0);
}

# verify that the target system is a cisco IOS
get_kb_item_or_exit("Host/Cisco/IOS/Version");

# Require local checks be enabled
if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

# Try to extract the FWSM version from the "show module" command
sock_g = ssh_open_connection();
if (!sock_g) exit(1, "Failed to open an SSH connection.");
fwsm_ssh1 = ssh_cmd(cmd:"show module", nosudo:TRUE, nosh:TRUE, cisco:TRUE);
ssh_close_connection();

if (!isnull(fwsm_ssh1) && "Firewall Module" >< fwsm_ssh1)
{
  # 4    6    Firewall Module                        WS-SVC-FWM-1      SAxxxxxxxxx
  module = eregmatch(string:fwsm_ssh1, pattern:"(\d+)\s+\d+\s*Firewall Module");

  if (!isnull(module))
  {
    # now execute the "show module #" command where # is the FWSM module number
    sock_g = ssh_open_connection();
    if (!sock_g) exit(1, "Failed to open an SSH connection.");
    fwsm_ssh2 = ssh_cmd(cmd:"show module " + module[1], nosudo:TRUE, nosh:TRUE, cisco:TRUE);
    ssh_close_connection();

    if (!isnull(fwsm_ssh2) && "Firewall Module" >< fwsm_ssh2)
    {
      # Mod MAC addresses                     Hw     Fw           Sw           Status
      # --- --------------------------------- ------ ------------ ------------ -------
      # 4   0003.e4xx.xxxx to 0003.e4xx.xxxx  3.0    7.2(1)       3.2(3)       Ok
      version = eregmatch(string:fwsm_ssh2, pattern:"[\r\n][^\r\n]+\s+([0-9][0-9\.\(\)]+)\s+Ok");

      if (!isnull(version))
      {
        report_and_exit(ver:version[1], source:'SSH');
        # never reached
      }
    }
  }
}

exit(0, 'The Cisco FWSM version is not available (the remote host may not be Cisco FWSM).');
