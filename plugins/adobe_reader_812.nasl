#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(30200);
  script_version("$Revision: 1.34 $");
  script_cvs_date("$Date: 2017/04/27 14:49:39 $");

  script_cve_id(
    #"CVE-2007-4768",  heap overflow in PCRE library
    "CVE-2007-5659",
    "CVE-2007-5663",
    "CVE-2007-5666",
    "CVE-2008-0655",
    "CVE-2008-0667",
    "CVE-2008-0726",
    "CVE-2008-2042"
  );
  script_bugtraq_id(27641);
  script_osvdb_id(41492, 41493, 41494, 41495, 42683, 44998, 46549);

  script_name(english:"Adobe Reader < 7.1.0 / 8.1.2 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Adobe Reader");

  script_set_attribute(attribute:"synopsis", value:
"The PDF file viewer on the remote Windows host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Reader installed on the remote host is earlier
than 8.1.2 or 7.1.0. Such versions are reportedly affected by multiple
vulnerabilities :

  - A design error vulnerability may allow an attacker to
    gain control of a user's printer.

  - Multiple stack-based buffer overflows may allow an
    attacker to execute arbitrary code subject to the
    user's privileges.

  - Insecure loading of 'Security Provider' libraries may
    allow for arbitrary code execution.

  - An insecure method exposed by the JavaScript library
    in the 'EScript.api' plug-in allows direct control
    over low-level features of the object, which allows
    for execution of arbitrary code as the current user.

  - Two vulnerabilities in the unpublicized function
    'app.checkForUpdate()' exploited through a callback
    function could lead to arbitrary code execution in
    Adobe Reader 7.");
  # http://www.verisigninc.com/en_US/products-and-services/network-intelligence-availability/idefense/public-vulnerability-reports/articles/index.xhtml?id=655
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8619fcdc");
  # http://www.verisigninc.com/en_US/products-and-services/network-intelligence-availability/idefense/public-vulnerability-reports/articles/index.xhtml?id=656
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1d74fcf2" );
  # http://www.verisigninc.com/en_US/products-and-services/network-intelligence-availability/idefense/public-vulnerability-reports/articles/index.xhtml?id=657
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4c30fbc0" );
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-08-004.html" );
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2008/Feb/79" );
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2008/Feb/103" );
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2008/Feb/104" );
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2008/Feb/105" );
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2008/Feb/146" );
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2008/May/140" );
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2008/May/141" );
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/acrobat/release-note/reader-acrobat-8-1-2.html" );
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/advisories/apsa08-01.html" );
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb08-13.html" );
  script_set_attribute(attribute:"solution", value:"Upgrade to Adobe Reader 8.1.2 / 7.1.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Adobe Collab.collectEmailInfo() Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_cwe_id(94, 119, 189, 399);

  script_set_attribute(attribute:"patch_publication_date", value:"2008/02/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/02/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:acrobat_reader");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2008-2017 Tenable Network Security, Inc.");

  script_dependencies("adobe_reader_installed.nasl");
  script_require_keys("SMB/Acroread/Version");
  exit(0);
}

include("global_settings.inc");
include("audit.inc");

info = NULL;
vers = get_kb_list('SMB/Acroread/Version');
if (isnull(vers)) exit(0, 'The "SMB/Acroread/Version" KB item is missing.');

foreach ver (vers)
{
  if (ver && ver =~ "^([0-6]\.|7\.0|8\.(0\.|1\.[01][^0-9.]?))")
  {
    path = get_kb_item('SMB/Acroread/'+ver+'/Path');
    if (isnull(path)) exit(1, 'The "SMB/Acroread/'+ver+'/Path" KB item is missing.');

    verui = get_kb_item('SMB/Acroread/'+ver+'/Version_UI');
    if (isnull(verui)) exit(1, 'The "SMB/Acroread/'+ver+'/Version_UI" KB item is missing.');

    info += '  - ' + verui + ', under ' + path + '\n';
  }
}

if (isnull(info)) exit(0, 'The remote host is not affected.');

if (report_verbosity > 0)
{
  if (max_index(split(info)) > 1) s = "s of Adobe Reader are";
  else s = " of Adobe Reader is";

  report =
    '\nThe following vulnerable instance'+s+' installed on the'+
    '\nremote host :\n\n'+
    info;
  security_hole(port:get_kb_item("SMB/transport"), extra:report);
}
else security_hole(get_kb_item("SMB/transport"));
