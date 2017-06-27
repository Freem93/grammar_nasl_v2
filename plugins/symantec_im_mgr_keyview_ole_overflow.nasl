#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(45018);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/12/14 20:33:27 $");

  script_cve_id("CVE-2009-3032", "CVE-2009-3036");
  script_bugtraq_id(38241, 38468);
  script_osvdb_id(62446, 62743);
  script_xref(name:"Secunia", value:"38809");

  script_name(english:"Symantec IM Manager 8.x < 8.3.14 (SYM10-005 and SYM10-006)");
  script_summary(english:"Checks build version number");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The instant messaging security application running on the remote
Windows host may be affected by multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"A version of Symantec IM Manager 8.x earlier than 8.3.14 is installed
on the remote Windows host.  Such versions may be affected by one or
both of the following vulnerabilities :

  - An integer overflow vulnerability in the third-party 
    Autonomy KeyView module can be triggered when parsing
    a specially crafted OLE document and lead to a heap
    overflow and execution of arbitrary code. 
    (CVE-2009-3032)

  - The IM Manager console fails to properly filter user
    input from non-privileged users with authorized access 
    to the console, which can be exploited to inject
    arbitrary HTML or script code into a user's browser to
    be executed within the security context of the affected 
    site. (CVE-2009-3036)"
  );
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8c5c8bce");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2010/Mar/109");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1b9ba8c5");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9374523c");
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Symantec IM Manager 8.4.13 (build 8.4.1362) or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(79, 189);

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/03/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/03/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:im_manager");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("symantec_im_mgr_installed.nasl");
  script_require_keys("SMB/Symantec/im_mgr/Build", "SMB/Symantec/im_mgr/Path");
  script_require_ports(139, 445);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");


build = get_kb_item('SMB/Symantec/im_mgr/Build');
if (isnull(build)) exit(1, "The 'SMB/Symantec/im_mgr/Build' KB item is missing.");

path = get_kb_item('SMB/Symantec/im_mgr/Path');
if (isnull(path)) exit(1, "The 'SMB/Symantec/im_mgr/Path' KB item is missing.");

build_fields = split(build, sep:'.', keep:FALSE);
for (i=0; i<max_index(build_fields); i++)
  build_fields[i] = int(build_fields[i]);

# Only the 8.x branch is affected.
if (
  build_fields[0] == 8 &&
  (
    build_fields[1] < 4 ||
    (build_fields[1] == 4 && build_fields[2] < 1362)
  )
)
{
  port = get_kb_item("SMB/transport");

  if (report_verbosity > 0)
  {
    report = '\n  Path                    : '+path+
             '\n  Installed build version : '+build+
             '\n  Fixed build version     : 8.4.1362\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else exit(0, "Build version "+build+" is installed and not affected.");
