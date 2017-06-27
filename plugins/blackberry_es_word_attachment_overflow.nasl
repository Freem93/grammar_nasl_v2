#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(20950);
  script_version("$Revision: 1.15 $");

  script_cve_id("CVE-2005-2341", "CVE-2006-0761");
  script_bugtraq_id(16098, 16590);
  script_osvdb_id(22181, 23247);
  script_xref(name:"Secunia", value:"18277");

  script_name(english:"BlackBerry Enterprise Server Attachment Handling Buffer Overflows");
  script_summary(english:"Checks version number of BlackBerry Enterprise Server");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows application is affected by multiple buffer overflow
vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The version of BlackBerry Enterprise Server on the remote host
reportedly contains flaws in its handling of Word and TIFF document
attachments that may result in buffer overflows when a user opens a
malformed file on a BlackBerry device.  A remote attacker may be able
to exploit this issue to execute code on the affected host subject to
the privileges under which the application runs, generally
'Administrator'." );
 # http://voices.washingtonpost.com/securityfix/2006/01/security_hole_claimed_for_blac_1.html
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0a5a9ceb" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c224cef8" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f9d6cf39" );
 script_set_attribute(attribute:"solution", value:
"Install the appropriate service pack / hotfix as described in the
vendor advisory." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:W/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/02/20");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/12/30");
 script_cvs_date("$Date: 2013/03/13 19:01:27 $");
script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:rim:blackberry_enterprise_server");
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Gain a shell remotely");
  script_copyright(english:"This script is Copyright (C) 2006-2013 Tenable Network Security, Inc.");
  script_dependencies("blackberry_es_installed.nasl");
  script_require_keys("BlackBerry_ES/Product", "BlackBerry_ES/Version");

  exit(0);
}


include("smb_func.inc");


prod = get_kb_item("BlackBerry_ES/Product");
ver = get_kb_item("BlackBerry_ES/Version");
if (prod && ver) {
  if (
    (
      "Domino" >< prod && 
      # fixed in 4.0.3 Hotfix 4 (Bundle 18)
      ver =~ "^([0-3]\..*|4\.0\.([0-2].*|3( Hotfix [1-3])?)) \(Bundle"
    ) ||
    (
      "Exchange" >< prod && 
      # fixed in 4.0.3 Hotfix 3 (Bundle 16)
      ver =~ "^([0-3]\..*|4\.0\.([0-2].*|3( Hotfix [12])?)) \(Bundle"
    ) ||
    (
      "GroupWise" >< prod && 
      # fixed in 4.0.3 Hotfix 1 (Bundle 17)
      ver =~ "^([0-3]\..*|4\.0\.([0-2].*|3)) \(Bundle"
    )
  ) {
    security_hole(kb_smb_transport());
  }
}
