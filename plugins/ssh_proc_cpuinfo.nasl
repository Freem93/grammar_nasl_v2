#TRUSTED 2ee47585a30594138a420f4f8527fb94a7d61d12ee6513908f92651676de8fe076f02ae2cd65072284cc7b719a3c0516676849b54c3c479e84ff055caac56711618cf5b125d030a718cb7e008659d2accd547432ff6b2e738913282d40083e8e3a85c9905a0845f20e795b7025e621a6e76d661d868207f8d7be504cd231faf06c5bedaf83794c7fcfa943127c9b87b8dd611d30a1e7d62f66561a1d37c948458490ab3261adbe9cc6b86b149c333137a04a3f2ffa0368baf617762fd29fee0d7cdc9935addaa7a5f7606b51ddb5488f7c96b2bc86619f6fc9fac0d7364ed5b20c53ff1ed256c2789466d7a5c53d8785c016b43c2fd8242804b375ac7b810748805bf7441265b8ec93fc5a5dcb40f07a6f614f0582fe2b5ce9bab51f34b91e06b16a5a6f03253f0a2c6697527ca01764d00930aa645f2f9683645ce943040e2540814802c2156bcfaf1bad82b624ccbf1a401b8568fc65753986a122359a86eda43e8af4815602469fcfb6f91f132a75a73db634a292253d76fe1dd8537f70d46a27217b6458382854496f49a1f550f5bbbaaaba8561072ce1f44c84fb84533a2e16703779e287431509e900393a0f4f99f757da3b51cf5a25b2ba989213393e64e8789e643015c10af88d4ef7e73f589b9554376fb2b607a3db5ef3c1e32c69c1c71948014187a9271b450caf53384efbfe9f1720aa437c850874e7562b9675
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56299);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2011/09/26");

  script_name(english:"Linux /proc/cpuinfo");
  script_summary(english:"Read /proc/cpuinfo");

  script_set_attribute(attribute:"synopsis", value:
"The processor's type and features can be read.");
  script_set_attribute(attribute:"description", value:
"/proc/cpuinfo could be read.  This file provides information on the
processor's type and features on Linux systems.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/09/26");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011 Tenable Network Security, Inc.");
  script_family(english:"Misc.");

  script_dependencies("ssh_settings.nasl", "ssh_get_info.nasl");
  script_require_keys('HostLevelChecks/proto');
  exit(0);
}

include("ssh_func.inc");
include("telnet_func.inc");
include("hostlevel_funcs.inc");

if (!get_kb_item('HostLevelChecks/proto')) exit(0, "Local checks are not enabled for the remote host.");

uname = get_kb_item("Host/uname");
if ("Linux" >!< uname) exit(0, 'The remote host is not running Linux.');

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

cmd = 'LC_ALL=C cat /proc/cpuinfo';
buf = info_send_cmd(cmd: cmd);
if (egrep(string:buf, pattern:'^processor[ \t]*:'))
{
  set_kb_item(name:'Host/proc/cpuinfo', value: buf);
  m = eregmatch(string: buf, pattern:'\nmodel name[ \t]*:[ \t]*(.*[^ \t])[ \t]*\n');
  if (! isnull(m))
    set_kb_item(name:'Host/proc/cpu_model_name', value: m[1]);
  exit(0);
}
else exit(1, "/proc/cpuinfo could not be read.");
