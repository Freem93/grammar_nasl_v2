#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69954);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2013/09/19 10:58:21 $");

  script_cve_id("CVE-2011-0963");
  script_bugtraq_id(47092);
  script_osvdb_id(72608);
  script_xref(name:"CISCO-BUG-ID", value:"CSCtj66922");
  script_xref(name:"IAVB", value:"2011-B-0055");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20110330-nac");

  script_name(english:"Cisco Network Admission Control Guest Server System Software Authentication Bypass (cisco-sa-20110330-nac)");
  script_summary(english:"Checks the NAC version");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device is missing a vendor-supplied security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Cisco Network Admission Control (NAC) Manager may be
affected by an access restriction bypass vulnerability in the RADIUS
authentication software.  This vulnerability could allow a
remote/unauthenticated attacker access to a protected network."
  );
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20110330-nac
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?59df77c3");
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20110330-nac."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:nac_guest_server");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/03/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/18");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_nac_version.nasl");
  script_require_keys("Host/Cisco/NAC/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");

version = get_kb_item_or_exit("Host/Cisco/NAC/Version");

flag = 0;
fixed_version = "";

if (ver_compare(ver:version, fix:"2.0.3", strict:FALSE) == -1)
{
  flag++;
  fixed_version = "2.0.3";
}

if (flag)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version;
    security_warning(port:0, extra:report);
  }
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
