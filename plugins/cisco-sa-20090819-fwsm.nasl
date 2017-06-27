#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69923);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/01/15 16:37:15 $");

  script_cve_id("CVE-2009-0638");
  script_bugtraq_id(36085);
  script_osvdb_id(57257);
  script_xref(name:"CISCO-BUG-ID", value:"CSCsz97207");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20090819-fwsm");

  script_name(english:"Firewall Services Module Crafted ICMP Message (cisco-sa-20090819-fwsm)");
  script_summary(english:"Checks the FWSM version");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device is missing a vendor-supplied security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Cisco Firewall Services Module (FWSM) for Cisco Catalyst
6500 Series Switches and Cisco 7600 Series Routers may be affected by a
denial of service (DoS) condition.  An attacker can trigger the DoS
condition by sending a specially crafted ICMP packet to the device. 
This will cause the network processor to stop working and result in the
DoS condition."
  );
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20090819-fwsm
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6a37a09f");
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20090819-fwsm."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:firewall_services_module");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/08/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/08/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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
# 2.x	migrate to 3.x or 4.x
if (version =~ "^2\.")
{
  flag++;
  fixed_version = "3.x or 4.x series";
}

# 3.1	< 3.1(16)
if ( (version =~ "^3\.1($|\.|\()") && (cisco_gen_ver_compare(a:version, b:"3.1(16)") < 0) )
{
  flag++;
  fixed_version = "3.1(16)";
}

# 3.2	< 3.2(13)
if ( (version =~ "^3\.2($|\.|\()") && (cisco_gen_ver_compare(a:version, b:"3.2(13)") < 0) )
{
  flag++;
  fixed_version = "3.2(13)";
}

# 4.0	< 4.0(6)
if ( (version =~ "^4\.0($|\.|\()") && (cisco_gen_ver_compare(a:version, b:"4.0(6)") < 0) )
{
  flag++;
  fixed_version = "4.0(6)";
}

if (flag)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version +
      '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
