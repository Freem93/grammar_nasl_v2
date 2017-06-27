#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(16126);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2014/07/03 01:08:29 $");

  script_cve_id("CVE-2004-1182");
  script_bugtraq_id(12227);
  script_osvdb_id(12859);

  script_name(english:"HylaFAX Remote Access Control Bypass");
  script_summary(english:"Determines if HylaFAX is vulnerable to an access control bypass.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains an application that is affected by an access
control bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running HylaFAX, a fax transmission software.

It is reported that HylaFAX is prone to an access control bypass
vulnerability. An attacker, exploiting this flaw, may be able to gain
unauthorized access to the service.");
  script_set_attribute(attribute:"see_also", value:"http://bugs.hylafax.org//show_bug.cgi?id=610");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 4.2.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_publication_date", value:"2005/01/11");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hylafax:hylafax");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2014 Tenable Network Security, Inc.");
  script_family(english:"Misc.");

  script_dependencies("hylafax_detect.nbin");
  script_require_keys("hylafax/installed", "hylafax/version", "Settings/ParanoidReport");
  script_require_ports("Services/hylafax", 4559);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

port = get_service(svc:"hylafax", default:4559, exit_on_fail:TRUE);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

banner = get_kb_item_or_exit("hylafax/banner");
version = get_kb_item_or_exit("hylafax/version");

fixed = '4.2.1';

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (
  ver[0] < 4 ||
  ver[0] == 4 && ver[1] < 2 ||
  ver[0] == 4 && ver[1] == 2 && ver[2] < 1 ||
  ver[0] == 4 && ver[1] == 2 && ver[2] == 1 && ("beta" >< version)
  )
{
 if (report_verbosity > 0)
  {
    report =
      '\n  Source            : ' + banner +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "HylaFAX+", port, version);
