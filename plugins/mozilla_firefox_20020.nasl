#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(35251);
  script_version("$Revision: 1.9 $");

  script_cve_id("CVE-2008-5507");
  script_osvdb_id(51292);

  script_name(english:"Firefox < 2.0.0.20 Cross Domain Data Theft");
  script_summary(english:"Checks version of Firefox");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser that is affected by a
cross domain data theft vulnerability." );
 script_set_attribute(attribute:"description", value:
"The installed version of Firefox is earlier than 2.0.0.20.  Such
versions shipped without a fix for a security issue that was
reportedly fixed in version 2.0.0.19. Specifically :

  - A website may be able to access a limited amount of 
    data from a different domain by loading a same-domain 
    JavaScript URL which redirects to an off-domain target
    resource containing data which is not parsable as 
    JavaScript. (MFSA 2008-65)

Note that Mozilla is not planning further security / stability
updates for Firefox 2." );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-65.html" );
 # https://blog.mozilla.org/blog/2008/12/19/firefox-20020-now-available-for-download/
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2f23d29d" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Firefox 2.0.0.20." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
 script_cwe_id(200);

 script_set_attribute(attribute:"plugin_publication_date", value: "2008/12/22");
 script_set_attribute(attribute:"patch_publication_date", value: "2008/12/16");
 script_cvs_date("$Date: 2013/05/23 15:37:57 $");
script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2008-2013 Tenable Network Security, Inc.");
  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Firefox/Version");
  exit(0);
}

include("mozilla_version.inc");
port = get_kb_item_or_exit("SMB/transport"); 

installs = get_kb_list("SMB/Mozilla/Firefox/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Firefox");

mozilla_check_version(installs:installs, product:'firefox', esr:FALSE, fix:'2.0.0.20', severity:SECURITY_WARNING);