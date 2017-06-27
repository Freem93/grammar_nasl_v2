#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(34695);
  script_version("$Revision: 1.27 $");
  script_cvs_date("$Date: 2016/11/11 19:58:28 $");

  script_cve_id(
    "CVE-2008-2549", 
    "CVE-2008-2992", 
    "CVE-2008-4812", 
    "CVE-2008-4813",
    "CVE-2008-4814", 
    "CVE-2008-4816", 
    "CVE-2008-4817", 
    "CVE-2008-5364"
  );
  script_bugtraq_id(29420, 30035, 32100, 32103, 32105);
  script_osvdb_id(46211, 49520, 49541, 50243, 50245, 50246, 50247, 50639);
  script_xref(name:"Secunia", value:"29773");

  script_name(english:"Adobe Reader < 8.1.3 / 9.0 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Adobe Reader");

  script_set_attribute(attribute:"synopsis", value:
"The PDF file viewer on the remote Windows host is affected by multiple
vulnerabilities." );
  script_set_attribute(attribute:"description", value:
"The version of Adobe Reader installed on the remote host is earlier
than 8.1.3.  Such versions are reportedly affected by multiple
vulnerabilities :

  - There is a publicly-published denial of service issue
    (CVE-2008-2549).

  - A stack-based buffer overflow when parsing format 
    strings containing a floating point specifier in the 
    'util.printf()' JavaScript function may allow an
    attacker to execute arbitrary code (CVE-2008-2992).

  - Multiple input validation errors could lead to code
    execution (CVE-2008-4812).

  - Multiple input validation issues could lead to remote
    code execution. (CVE-2008-4813)

  - A heap corruption vulnerability in an AcroJS function
    available to scripting code inside of a PDF document
    could lead to remote code execution. (CVE-2008-4817)

  - An input validation issue in the Download Manager used 
    by Adobe Reader could lead to remote code execution 
    during the download process (CVE-2008-5364).

  - An issue in the Download Manager used by Adobe Reader 
    could lead to a user's Internet Security options being 
    changed during the download process (CVE-2008-4816).

  - An input validation issue in a JavaScript method could 
    lead to remote code execution (CVE-2008-4814)." );
  script_set_attribute(attribute:"see_also", value:"http://secunia.com/secunia_research/2008-14/" );
  script_set_attribute(attribute:"see_also", value:"http://www.coresecurity.com/content/adobe-reader-buffer-overflow" );
  # http://www.verisigninc.com/en_US/products-and-services/network-intelligence-availability/idefense/public-vulnerability-reports/articles/index.xhtml?id=754
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4d149b32" );
  # http://www.verisigninc.com/en_US/products-and-services/network-intelligence-availability/idefense/public-vulnerability-reports/articles/index.xhtml?id=755
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b4f90b46" );
  # http://www.verisigninc.com/en_US/products-and-services/network-intelligence-availability/idefense/public-vulnerability-reports/articles/index.xhtml?id=756
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f6f3b943" );
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-08-072" );
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-08-073" );
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-08-074" );
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/498027/30/0/threaded" );
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/498032/30/0/threaded" );
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb08-19.html" );
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Reader 9.0 / 8.1.3 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Adobe util.printf() Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(20, 119, 399);

  script_set_attribute(attribute:"plugin_publication_date", value: "2008/11/04");
  script_set_attribute(attribute:"patch_publication_date", value: "2008/11/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:acrobat_reader");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

  script_dependencies("adobe_reader_installed.nasl");
  script_require_keys("SMB/Acroread/Version");
  exit(0);
}

#

include("global_settings.inc");

info = NULL;
vers = get_kb_list('SMB/Acroread/Version');
if (isnull(vers)) exit(0, 'The "SMB/Acroread/Version" KB item is missing.');

foreach ver (vers)
{
  if (
    ver && 
    (
      ver =~ "^[0-6]\." ||
      ver =~ "^7\.(0\.|1\.0\.)" ||
      ver =~ "^8\.(0\.|1\.[0-2][^0-9.]?)"
    )
  )
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
