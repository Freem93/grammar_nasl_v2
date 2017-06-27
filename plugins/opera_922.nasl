#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(25755);
  script_version("$Revision: 1.18 $");

  script_cve_id("CVE-2007-3142", "CVE-2007-3819", "CVE-2007-3929");
  script_bugtraq_id(24352, 24917, 24970);
  script_osvdb_id(38122, 38123, 43463);

  script_name(english:"Opera < 9.22 Multiple Vulnerabilities");
  script_summary(english:"Checks version number of Opera");

 script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
issues." );
 script_set_attribute(attribute:"description", value:
"The version of Opera installed on the remote host reportedly can be
tricked into attempting to dereference an invalid object pointer when
parsing a specially crafted BitTorrent header. This could cause the
application to crash or even lead to execution of arbitrary code
subject to the privileges of the current user. 

Successful exploitation requires that a user on the affected host
click on a link to a BitTorrent file and then remove the entry from
Opera's download manager. 

In addition, it can mistakenly display the end of a 'data:' URL rather
than the beginning, which can lead to spoofing of trusted sites." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?16e8f6cd" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2007/Jul/405" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/473703/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://www.0x000000.com/?i=334" );
 script_set_attribute(attribute:"see_also", value:"http://www.opera.com/support/search/view/862/" );
 script_set_attribute(attribute:"see_also", value:"http://www.opera.com/support/search/view/863/" );
 script_set_attribute(attribute:"see_also", value:"http://www.opera.com/support/search/view/864/" );
 script_set_attribute(attribute:"see_also", value:"http://www.opera.com/docs/changelogs/windows/922/" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Opera version 9.22 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(119);
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/07/23");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/07/14");
 script_cvs_date("$Date: 2016/11/02 14:37:07 $");
script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/a:opera:opera_browser");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");

  script_dependencies("opera_installed.nasl");
  script_require_keys("SMB/Opera/Version_UI");

  exit(0);
}


include("global_settings.inc");


version_ui = get_kb_item("SMB/Opera/Version_UI");
if (isnull(version_ui)) exit(0);

if (version_ui =~ "^([0-8]\.|9\.([01][0-9]|2[01])($|[^0-9]))")
{
  if (report_verbosity)
  {
    report = string(
      "\n",
      "Opera version ", version_ui, " is currently installed on the remote host.\n"
    );
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));
}
