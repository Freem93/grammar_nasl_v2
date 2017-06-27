#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85911);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/09/14 13:50:03 $");

  script_cve_id("CVE-2015-2323");
  script_bugtraq_id(76047);
  script_osvdb_id(125579);
  
  script_name(english:"Fortinet FortiOS 5.0.x < 5.0.12 / 5.2.x < 5.2.4 Weak Ciphers (FG-IR-15-021)");
  script_summary(english:"Checks the version of FortiOS.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host supports weak ciphers");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Fortinet FortiOS that is 5.0.x
prior to 5.0.12 or 5.2.x prior 5.2.4. It is, therefore, affected by a
flaw when connecting to a FortiGuard server via TLS due to the support
of weak ciphers such as anonymous, export, and RC4. A
man-in-the-middle attacker can exploit this to downgrade the TLS
cipher suite and conduct attacks on the TLS connection.");
  script_set_attribute(attribute:"see_also", value:"http://www.fortiguard.com/advisory/FG-IR-15-021");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Fortinet FortiOS 5.0.12 / 5.2.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/07/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fortinet:fortios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("fortinet_version.nbin");
  script_require_keys("Host/Fortigate/model", "Host/Fortigate/version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app_name = "FortiOS";

version = get_kb_item_or_exit("Host/Fortigate/version");
model = get_kb_item_or_exit("Host/Fortigate/model");

if (version =~ "^5\.0\.")
{
  fix = "5.0.12";
}
else if (version =~ "^5\.2\.")
{
  fix = "5.2.4";
}
else audit(AUDIT_INST_VER_NOT_VULN, app_name, version);

if (ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Model             : ' + model +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix +
      '\n';
    security_warning(extra:report, port:0);
  }
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, app_name, version);
