#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69949);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/01/15 16:37:15 $");

  script_cve_id("CVE-2008-1155");
  script_bugtraq_id(28807);
  script_osvdb_id(44422);
  script_xref(name:"CISCO-BUG-ID", value:"CSCsj33976");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20080416-nac");

  script_name(english:"Cisco Network Admission Control Shared Information Disclosure (cisco-sa-20080416-nac)");
  script_summary(english:"Checks the NAC version.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device is missing a vendor-supplied security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Cisco Network Admission Control (NAC) is affected by an
information disclosure vulnerability. This vulnerability allows an
attacker to obtain a shared secret from the error logs, which are sent
over the network. This shared secret is used by Cisco Clean Access
Server (CAS) and the Cisco Clean Access Manager (CAM). If an attacker
is able to obtain this shared secret, they can gain complete control
of the remote device."
  );
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20080416-nac
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?94cf52f5");
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20080416-nac."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(200);

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/04/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:network_admission_control");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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

if (version =~ "^3\.5($|\.)")
{
  flag++;
  fixed_version = "upgrade to 3.6.4.4, 4.0.6, or 4.1.2";
}

if ((version =~ "^3\.6($|\.)") && (ver_compare(ver:version, fix:"3.6.4.4", strict:FALSE) == -1))
{
  flag++;
  fixed_version = "3.6.4.4";
}

if ((version =~ "^4\.0($|\.)") && (ver_compare(ver:version, fix:"4.0.6", strict:FALSE) == -1))
{
  flag++;
  fixed_version = "4.0.6";
}

if ((version =~ "^4\.1($|\.)") && (ver_compare(ver:version, fix:"4.1.2", strict:FALSE) == -1))
{
  flag++;
  fixed_version = "4.1.2";
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
