#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(31864);
  script_version("$Revision: 1.14 $");

  script_cve_id("CVE-2008-1380");
  script_bugtraq_id(28818);
  script_osvdb_id(44467);
  script_xref(name:"Secunia", value:"29787");

  script_name(english:"Firefox < 2.0.0.14 Javascript Garbage Collector DoS ");
  script_summary(english:"Checks version of Firefox");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser that may allow
arbitrary code execution." );
 script_set_attribute(attribute:"description", value:
"The installed version of Firefox contains a stability problem that
could result in a crash during JavaScript garbage collection. 
Although there are no examples of this extending beyond a crash,
similar issues in the past have been shown to allow arbitrary code
execution." );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-20.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Firefox 2.0.0.14 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(399);

 script_set_attribute(attribute:"plugin_publication_date", value: "2008/04/17");
 script_set_attribute(attribute:"patch_publication_date", value: "2008/04/16");
 script_cvs_date("$Date: 2016/05/16 14:12:50 $");
script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Firefox/Version");
  exit(0);
}

include("mozilla_version.inc");
port = get_kb_item_or_exit("SMB/transport"); 

installs = get_kb_list("SMB/Mozilla/Firefox/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Firefox");

mozilla_check_version(installs:installs, product:'firefox', esr:FALSE, fix:'2.0.0.14', severity:SECURITY_HOLE);