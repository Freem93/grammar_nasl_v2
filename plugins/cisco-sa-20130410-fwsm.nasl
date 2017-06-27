#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69924);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/04 18:02:13 $");

  script_cve_id("CVE-2013-1149", "CVE-2013-1155");
  script_bugtraq_id(59001, 59002);
  script_osvdb_id(92212, 92213);
  script_xref(name:"CISCO-BUG-ID", value:"CSCtg02624");
  script_xref(name:"CISCO-BUG-ID", value:"CSCud20267");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20130410-fwsm");

  script_name(english:"Multiple Vulnerabilities in Cisco Firewall Services Module Software (cisco-sa-20130410-fwsm)");
  script_summary(english:"Checks the FWSM version");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device is missing a vendor-supplied security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Cisco Firewall Services Module (FWSM) for Cisco Catalyst
6500 Series Switches and Cisco 7600 Series Routers may be affected by
the following vulnerabilities :

  - A flaw in the FWSM software could allow remote attackers
    to cause a denial of service (DoS) condition via a
    crafted IKEv1 message. (CVE-2013-1149)

  - The FWSM HTTP Proxy auth-proxy functionality could allow
    remote attackers to cause a DoS condition via a
    specially crafted URL. (CVE-2013-1155)"
  );
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20130410-fwsm
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?574f7790");
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20130410-fwsm."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:firewall_services_module");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/04/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_fwsm_version.nasl");
  script_require_keys("Host/Cisco/FWSM/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");

version = get_kb_item_or_exit("Host/Cisco/FWSM/Version");

flag = 0;
fixed_version = "";

# Affected versions:
# 3.1
if (version =~ "^3\.1($|\.|\()")
{
  flag++;
  fixed_version = "3.2 or later";
}

# 3.2   < 3.2(24.1)
if ( (version =~ "^3\.2($|\.|\()") && (cisco_gen_ver_compare(a:version, b:"3.2(24.1)") < 0) )
{
  flag++;
  fixed_version = "3.2(24.1)";
}

# 4.0
if (version =~ "^4\.0($|\.|\()")
{
  flag++;
  fixed_version = "4.1 or later";
}

# 4.1   < 4.1(11.1)
if ( (version =~ "^4\.1($|\.|\()") && (cisco_gen_ver_compare(a:version, b:"4.1(11.1)") < 0) )
{
  flag++;
  fixed_version = "4.1(11.1)";
}

if (flag)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version;
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
