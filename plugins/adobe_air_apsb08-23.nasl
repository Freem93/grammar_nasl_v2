#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(34815);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2017/04/25 14:28:28 $");

  script_cve_id("CVE-2007-4324", "CVE-2007-6243", "CVE-2008-3873", "CVE-2008-4401", "CVE-2008-4818",
                "CVE-2008-4819", "CVE-2008-4820", "CVE-2008-4821", "CVE-2008-4822", "CVE-2008-4823",
                "CVE-2008-4824", "CVE-2008-5108");
  script_bugtraq_id(25260, 26966, 31117, 32129, 32334);
  script_osvdb_id(
    41475,
    41487,
    48049,
    49753,
    49780,
    49781,
    49783,
    49785,
    49790,
    49915,
    49958,
    50126,
    50127,
    51567
  );
  script_xref(name:"Secunia", value:"32772");

  script_name(english:"Adobe AIR < 1.5 Multiple Vulnerabilities (APSB08-23)");
  script_summary(english:"Checks version of Adobe AIR");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a runtime environment that is
affected by multiple issues.");
  script_set_attribute(attribute:"description", value:
"According to its version number, an instance of Adobe AIR on the
remote Windows host is 1.1 or earlier.  Such versions are potentially
affected by several vulnerabilities (APSB08-23 / APSB08-22 / 
APSB08-20 / APSB08-18):

  - A potential port-scanning issue. (CVE-2007-4324)

  - Possible privilege escalation attacks against web 
    servers hosting Flash content and cross-domain policy 
    files.  (CVE-2007-6243)

  - Potential Clipboard attacks. (CVE-2008-3873)

  - FileReference upload and download APIs that don't
    require user interaction. (CVE-2008-4401)

  - A potential cross-site scripting vulnerability. 
    (CVE-2008-4818)

  - A potential issue that could be leveraged to conduct
    a DNS rebinding attack. (CVE-2008-4819)

  - An information disclosure issue affecting only the 
    ActiveX control. (CVE-2008-4820)

  - An information disclosure issue involving interpretation
    of the 'jar:' protocol and affecting only the plugin for 
    Mozilla browsers. (CVE-2008-4821)

  - An issue with policy file interpretation could 
    potentially lead to bypass of a non-root domain policy. 
    (CVE-2008-4822)

  - A potential HTML injection issue involving an 
    ActionScript attribute. (CVE-2008-4823)

  - Multiple input validation errors could potentially lead
    to execution of arbitrary code. (CVE-2008-4824)

  - An Adobe AIR application that loads data from an 
    untrusted source could allow an attacker to execute 
    untrusted JavaScript with elevated privileges. 
    (CVE-2008-5108)");
  # https://web.archive.org/web/20090213183551/http://www.adobe.com/support/security/bulletins/apsb08-23.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0d47175e");
  script_set_attribute(attribute:"solution", value:"Upgrade to Adobe AIR version 1.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 79, 94, 200, 264);

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/11/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/11/17");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:air");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2008-2017 Tenable Network Security, Inc.");
  script_dependencies("adobe_air_installed.nasl");
  script_require_keys("SMB/Adobe_AIR/Version");
  exit(0);
}

#

include("global_settings.inc");


version_ui = get_kb_item("SMB/Adobe_AIR/Version_UI");
version = get_kb_item("SMB/Adobe_AIR/Version");
if (isnull(version)) exit(0);

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (
  ver[0] < 1 ||
  (
    ver[0] == 1 && 
    (
      ver[1] < 5 ||
      (ver[1] == 5 && ver[2] == 0 && ver[3] < 7220)
    )
  )
)
{
  if (report_verbosity && version_ui)
  {
    report = string(
      "\n",
      "Adobe AIR ", version_ui, " is currently installed on the remote host.\n"
    );
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));
}
