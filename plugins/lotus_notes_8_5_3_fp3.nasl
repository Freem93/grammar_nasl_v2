#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63281);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2013/10/25 10:43:06 $");

  script_cve_id(
    "CVE-2012-4820",
    "CVE-2012-4821",
    "CVE-2012-4822",
    "CVE-2012-4823",
    "CVE-2012-4846"
  );
  script_bugtraq_id(55495, 56944);
  script_osvdb_id(87299, 87300, 87301, 87302, 88429);

  script_name(english:"IBM Lotus Notes 8.5.1 / 8.5.2 / 8.5.3 < 8.5.3 FP3 Multiple Vulnerabilities");
  script_summary(english:"Checks version of IBM Lotus Notes");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has software installed that is affected by multiple
vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host has a version of Lotus Notes 8.5.1, 8.5.2, or 8.5.3.x
prior to 8.5.3 Fix Pack 3 installed.  It is, therefore, reportedly
affected by the following vulnerabilities :

  - The included version of the IBM Java SDK contains a
    version of the IBM JRE that contains several errors
    that allow Java code execution outside the Java
    sandbox. (CVE-2012-4820, CVE-2012-4821, CVE-2012-4822,
    CVE-2012-4823)

  - Information disclosure is possible because the
    application does not set the 'HttpOnly' flag in the
    'Set-Cookie' HTTP header. This can allow client-side
    scripts to read or modify HTTP cookie information.
    (CVE-2012-4846)

Note that applying the Java patch (Reference #1616652) alone does not
correct the 'HttpOnly' information disclosure vulnerability.

Further note that in the case of version 8.5.3 Fix Pack 2, if the
Java patch (Reference #1616652) and the interim fix (853FP2IF3) have
been applied, this may be a false positive."
  );
  # https://www-304.ibm.com/connections/blogs/PSIRT/entry/security_bulletin_ibm_lotus_notes_domino_affected_by_vulnerabilities_in_ibm_jre_cve_2012_4820_cve_2012_4821_cve_2012_4822_cve_2012_4823?lang=en_us
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?856fbd02");
  # Interim fix 3 for 8.5.3 Fix Pack 2 (853FP2IF3)
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21620361");
  # Bulletin for Java issues
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21616652");
  # Java patch
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21617185");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Lotus Notes 8.5.3 Fix Pack 3 or later. Alternatively, if
version 8.5.3 Fix Pack 2 is in use, install the Java patch
(Reference #1616652) and the interim fix 853FP2IF3.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/09/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/11/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/12/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:lotus_notes");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2013 Tenable Network Security, Inc.");

  script_dependencies("lotus_notes_installed.nasl");
  script_require_keys("SMB/Lotus_Notes/Installed");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

appname = "IBM Lotus Notes";
kb_base = "SMB/Lotus_Notes/";

port = get_kb_item_or_exit('SMB/transport');
version = get_kb_item_or_exit(kb_base + 'Version');
path = get_kb_item_or_exit(kb_base + 'Path');
ver_ui = get_kb_item_or_exit(kb_base + 'Version_UI');

fix = '8.5.33.12320';

if (
  ver_ui =~ "^8\.5\.[1-3]($|[^0-9])" &&
  ver_compare(ver:version, fix:fix, strict:FALSE) == -1
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + ver_ui +
      '\n  Fixed version     : 8.5.3 FP3 (' + fix + ')' +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, appname, ver_ui, path);
