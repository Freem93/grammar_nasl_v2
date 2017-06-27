#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69816);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/09/09 15:37:52 $");

  script_cve_id("CVE-2012-3271");
  script_bugtraq_id(56597);
  script_osvdb_id(87614);

  script_name(english:"iLO 3 < 1.50 / iLO 4 < 1.13 Unspecified Information Disclosure");
  script_summary(english:"Checks version of HP Integrated Lights-Out (iLO).");

  script_set_attribute(attribute:"synopsis", value:
"The remote HP Integrated Lights-Out (iLO) server has an unspecified
information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its version number, the remote HP Integrated Lights-Out
(iLO) server is affected by an unspecified information disclosure
vulnerability.");
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c03515413
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2300d65c");
  script_set_attribute(attribute:"solution", value:
"For HP Integrated Lights-Out (iLO) 3, upgrade firmware to 1.50 or
later. For iLO 4, upgrade firmware to 1.13 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/11/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/09");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:integrated_lights-out_3_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:integrated_lights-out_4_firmware");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

  script_dependencies("ilo_detect.nasl");
  script_require_keys("Settings/ParanoidReport", "ilo/generation", "ilo/firmware");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

# Each generation has its own series of firmware version numbers.
generation = get_kb_item_or_exit("ilo/generation");
version = get_kb_item_or_exit("ilo/firmware");

# Firmware is unique to the generation of iLO.
if (generation == 3)
  fixed_version = "1.50";
else if (generation == 4)
  fixed_version = "1.13";
else
  audit(AUDIT_INST_VER_NOT_VULN, "iLO " + generation, version);

if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) >= 0)
  audit(AUDIT_INST_VER_NOT_VULN, "iLO " + generation, version);

report = NULL;
if (report_verbosity > 0)
{
  report =
    '\n Generation       : ' + generation +
    '\n Firmware version : ' + version +
    '\n Fixed version    : ' + fixed_version +
    '\n';
}

# Which service/port is vulnerable is unspecified in the bulletin.
security_hole(port:0, extra:report);
