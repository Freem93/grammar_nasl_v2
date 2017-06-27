#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(55535);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2012/03/20 17:24:43 $");

  script_cve_id("CVE-2011-1338");
  script_bugtraq_id(48562);
  script_osvdb_id(73619);

  script_name(english:"XnView < 1.98.1 Insecure Executable Loading");
  script_summary(english:"Checks XnView.exe's Product Version number");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Windows host contains an application that loads
executables in an insecure manner."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The version of XnView installed on the remote Windows host is earlier
than 1.98.1.  As such, it reportedly uses unsafe methods for
determining how to load executables.  Specifically, there is an issue
with the file search path, which could result in the insecure loading
of executables when using the 'Open containing folder' function. 

An attacker may be able to exploit this to execute arbitrary code with
the privileges of the running application."
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://jvndb.jvn.jp/en/contents/2011/JVNDB-2011-000050.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade to XnView version 1.98.1 or later as that reportedly resolves
the issue."
  );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/06/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/07/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/07/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:xnview:xnview");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2012 Tenable Network Security, Inc.");

  script_dependencies("xnview_rgbe_overflow.nasl");
  script_require_keys("SMB/XnView/Version");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");


kb_base = "SMB/XnView";
get_kb_item_or_exit(kb_base+"/Installed");
version = get_kb_item_or_exit(kb_base+"/Version", exit_code:1);
port = get_kb_item("SMB/transport");


# Check the version number.
ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (
  ver[0] < 1 ||
  (
    ver[0] == 1 &&
    (
      ver[1] < 98 ||
      (ver[1] == 98 && ver[2] < 1)
    )
  )
)
{
  if (report_verbosity > 0)
  {
    path = get_kb_item(kb_base+"/Path");
    if (isnull(path)) path = "n/a";

    report = 
      '\n  Path              : ' + path + 
      '\n  Installed version : ' + version + 
      '\n  Fixed version     : 1.98.1\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else exit(0, "The XnView " + version + " install is not affected.");
