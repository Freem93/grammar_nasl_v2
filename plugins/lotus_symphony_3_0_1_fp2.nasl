#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(63266);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2013/10/10 02:04:16 $");

  script_cve_id(
    "CVE-2012-0037", 
    "CVE-2012-1149", 
    "CVE-2012-2334", 
    "CVE-2012-2665"
  );
  script_bugtraq_id(56755);
  script_osvdb_id(
    80307,
    81988,
    82517,
    84440,
    84441,
    84442,
    88601,
    88602,
    88603
  );

  script_name(english:"IBM Lotus Symphony < 3.0.1 Fix Pack 2 Multiple Vulnerabilities");
  script_summary(english:"Checks version of IBM Lotus Symphony");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has an application installed that is affected by
multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of IBM Lotus Symphony is a version prior to 3.0.1 Fix 
Pack 2.  Such versions are affected by multiple vulnerabilities :

  - Flaws exist in the way certain XML components are
    processed for external entities in ODF documents.
    These flaws can be utilized to access and inject the
    content of local files into an ODF document without a
    user's knowledge or permission, or inject arbitrary code
    that would be executed when opened by the user.
    (CVE-2012-0037)

  - An integer overflow error exists in 'vclmi.dll' that
    can allow heap-based buffer overflows when handling
    embedded image objects. (CVE-2012-1149)

  - Memory checking errors exist in
    'filter/source/msfilter msdffimp.cxx' that can be
    triggered when processing PowerPoint graphics records.
    These errors can allow denial of service attacks.
    (CVE-2012-2334)

  - Errors exist related to XML tag handling and base64
    decoding that can lead to heap-based buffer overflows.
    (CVE-2012-2665)"
  );
  # http://www-03.ibm.com/software/lotus/symphony/buzz.nsf/web_DisPlayPlugin?open&unid=47F01C7A565AB6B885257AC5004E5713&category=announcements
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f0e3479c");
  # http://www-03.ibm.com/software/lotus/symphony/idcontents/releasenotes/en/readme_301fixpack2_standalone_long.htm
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d8edb1f9");
  script_set_attribute(attribute:"solution", value:"Upgrade to IBM Lotus Symphony 3.0.1 Fix Pack 2 (3.0.1.20121012-2300) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/03/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/11/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/12/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:lotus_symphony");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2013 Tenable Network Security, Inc.");

  script_dependencies("lotus_symphony_installed.nasl");
  script_require_keys("SMB/Lotus_Symphony/Installed");
  
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

appname = "Lotus Symphony";

kb_base = "SMB/Lotus_Symphony/";
port = get_kb_item("SMB/transport");

get_kb_item_or_exit(kb_base + "Installed");
version = get_kb_item_or_exit(kb_base + "Version");
ver_ui = get_kb_item_or_exit(kb_base + "Version_UI");
path = get_kb_item_or_exit(kb_base + "Path");

# extract build timestamp
item = eregmatch(pattern:"([0-9]+)-([0-9]+)$", string:version);
if (isnull(item)) exit(1, "Error parsing the version string ("+version+").");

# date/time
dt = int(item[1]);
tm = int(item[2]);

# Affected < 3.0.1 Fix Pack 2 (3.0.1.20121012-2300)
if (dt < 20121012 || (dt == 20121012 && tm < 2300))
{
  if (report_verbosity > 0)
  {
    report = '\n  Path              : ' + path + 
             '\n  Installed version : ' + ver_ui +
             '\n  Fixed version     : 3.0.1 Fix Pack 2 (3.0.1.20121012-2300)\n';
   security_hole(port:port,extra:report);
  }
  else security_hole(port);
  exit(0);
} 
else audit(AUDIT_INST_PATH_NOT_VULN, appname, ver_ui, path);
