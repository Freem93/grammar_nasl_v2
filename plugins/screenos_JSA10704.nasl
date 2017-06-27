#TRUSTED 42d2b16ad8d397087fa99d9da2ce0cf9414d0377b758594990af783fe35840a44a5ef7d8c9d42969175b3e036f29bc2c5c3e06cbdd22d26d3c8119659842fe73d5009747ea1e17ae419a43ac7512c4085d215c83b790d6eab5fb2c7511cf83db7c8a3613afc09e1bfe1f4f4b3f111d55e8a4e86e80630df66749f69575e80b79b5024ff6389d8e9cba163b86d8a9bf523fa2aa50c3a0635f34f4c237851c559259157bdde6d05f499c1c6ff7a2f8992a1b771bf441bebecba6f9883b4d64cc2d420edd2c19bbde641449cd4afc01fadb894849a4e3765d0489673f76e16293be48962b59fe735358b26f742aa97769e4cc44a9573ec81500c08614a0d7aeb34d776b0d83c4036eb9705d206550fe7671e266d7ae6dc72101e0e4ee586965453b1a6ad20e5dba5f3406a735c511f074e4c00d44b73822c76f7a478c7e39bc7b530954ce9207f6420259e35703587bae84d50db7c7d3b0210af877a72e230a588548f92369e6401cc381d3cf8483e1dd67246f25d1b3b787f70560a3e7a5aaca466a5600e8e187d71f08210d8cdcd9804b569a68a636c25429b9651ace22d330cc3d657bf8f6252dcc081cf8a7f6a9998067b4c1037a8d5543273c313f6f039870c59673db99bde646f7f531571d7103fd9dbc6515467dd2f1ed61239abbba8a6674a8ab37b6063f3cf61daae43ca67db5cfcd8d0e599baba55b769fba8c841247
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86610);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2016/04/24");

  script_cve_id("CVE-2015-7750");
  script_osvdb_id(128902);

  script_name(english:"Juniper ScreenOS < 6.3.0r20 L2TP DoS (JSA10704)");
  script_summary(english:"Checks version of ScreenOS.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Juniper ScreenOS prior to
6.3.0r20. It is, therefore, affected by a denial of service
vulnerability related to the handling of L2TP packets. An
unauthenticated, remote attacker can exploit this, via specially
crafted L2TP packet, to cause the system to reboot.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10704");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Juniper ScreenOS 6.3.0r20 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/10/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:screenos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("screenos_version.nbin");
  script_require_keys("Host/Juniper/ScreenOS/display_version", "Host/Juniper/ScreenOS/version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");

##
# Only systems with l2tp configured are vulnerable
##
function l2tp_configured()
{
  local_var ret,buf;

  ret = ssh_open_connection();
  if(!ret)
    exit(1, "ssh_open_connection() failed.");
  buf = ssh_cmd(cmd:'get config | include "l2tp"', nosh:TRUE, nosudo:TRUE, noexec:TRUE, cisco:FALSE);
  ssh_close_connection();
  if("set l2tp" >< tolower(buf))
    return TRUE;
  return FALSE;
}

app_name = "Juniper ScreenOS";
display_version = get_kb_item_or_exit("Host/Juniper/ScreenOS/display_version");
version = get_kb_item_or_exit("Host/Juniper/ScreenOS/version");
csp = get_kb_item("Host/Juniper/ScreenOS/csp");

if(isnull(csp))
  csp = "";

# Remove trialing 'a' if there, no 'a' versions fixes this
version = ereg_replace(pattern:"([0-9r\.]+)a$", replace:"\1", string:version);

# Check version
display_fix = "6.3.0r20";
fix = str_replace(string:display_fix, find:'r', replace:'.');

# CSPs
if(version =~ "^6\.3\.0\.13($|[^0-9])" && csp =~ "^dnd1")
  audit(AUDIT_INST_VER_NOT_VULN, app_name, display_version);
if(version =~ "^6\.3\.0\.18($|[^0-9])" && csp =~ "^dnc1")
  audit(AUDIT_INST_VER_NOT_VULN, app_name, display_version);

# If we're not 6.3.x or if we are greater than or at fix version, audit out
if(ver_compare(ver:version, fix:fix, strict:FALSE) >= 0)
  audit(AUDIT_INST_VER_NOT_VULN, app_name, display_version);

# We have various version sources for this, not all rely on local checks
note = FALSE; # Similar to cisco caveat
if(!isnull(get_kb_item("Host/local_checks_enabled")))
{
  if(!l2tp_configured())
    audit(AUDIT_HOST_NOT, "affected because l2tp is not enabled");
}
else
{
  note =
   '\n  Note: Nessus could not verify that L2TP is configured because' +
   '\n        local checks are not enabled. Only devices using L2TP'+
   '\n        are potentially vulnerable.';
}

port = 0;
if (report_verbosity > 0)
{
  report =
    '\n  Installed version : ' + display_version +
    '\n  Fixed version     : ' + display_fix;
  if(note)
    report += note;
  report += '\n';

  security_hole(extra:report, port:port);
}
else security_hole(port);
