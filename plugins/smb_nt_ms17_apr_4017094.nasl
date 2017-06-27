#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99289);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/05/01 17:35:41 $");

  script_cve_id("CVE-2013-6629");
  script_bugtraq_id(63676);
  script_osvdb_id(99711);
  script_xref(name:"IAVA", value:"2017-A-0103");
  script_xref(name:"MSKB", value:"4017094");

  script_name(english:"KB4017094: Security Update for the libjpeg Information Disclosure Vulnerability for Microsoft Silverlight 5 (April 2017)");
  script_summary(english:"Checks the version of npctrl.dll.");

  script_set_attribute(attribute:"synopsis", value:
"A web application framework running on the remote host is affected by
an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Silverlight 5 installed on the remote Windows host is
missing security update KB4017094. It is, therefore, affected by an
information disclosure vulnerability in the open-source libjpeg image
processing library due to improper handling of objects in memory. An
unauthenticated, remote attacker can exploit this to disclose
sensitive information that can be utilized to bypass ASLR security
protections.");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4017094/title");
  # https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2013-6629
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d5f07ab5");
  script_set_attribute(attribute:"solution", value:
"Apply security update KB4017094.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:X/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/11/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:silverlight");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("silverlight_detect.nasl");
  script_require_keys("SMB/Registry/Enumerated", "SMB/Silverlight/Version");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

version = get_kb_item_or_exit("SMB/Silverlight/Version");

if (!isnull(version) && version =~ "^5\.")
{
  fix = "5.1.50906.0";
}
else audit(AUDIT_HOST_NOT, 'affected');

if (ver_compare(ver:version, fix:fix) == -1)
{
  path = get_kb_item("SMB/Silverlight/Path");
  if (isnull(path)) path = 'n/a';

  report =
    '\n  Path              : ' + path +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix +
    '\n';

  security_report_v4(port:get_kb_item("SMB/transport"), severity:SECURITY_WARNING, extra:report);
}
else audit(AUDIT_HOST_NOT, 'affected');
