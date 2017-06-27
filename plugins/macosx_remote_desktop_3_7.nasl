#TRUSTED 2f43a3a6863d87ce12ff2fe32dc625229e87bcd7bea30ea4e5b88f230ed8fbdbfabe622306aa176644d8909d75b7881e8bc21534e6146bc2df979afba1f05050a4733a7126ae7028ab3a1d8aaa973731baf520c9382b482087b8247b3774a9ffcb68c83435418120fa4e67bbb1d4827418a5c70050d08735e33a1aa7e30f7f213b2b6e907aa70898ff3a5c4bd5f030db78d5b8d56a08d68ce90b357924d3f9b3551b8d5ed56e3b7b0ef6b7665e6f1f71dcfcbd32d04615d8c04002f897b8351e89dae36324d81c3aae24d3f46687e3c4adf63e31ef5189b3abbcc6997d1fd43820910eeea579c6afa70453ef1add75da57dbfb0c14971dcb4716890ccdbcfd80f3edc7ec5274b8562f9f1795f5b4b4f368e2e9b6b19cd5f5a1b56d429a33d911a8045d8691ea4f130a2926e7be5cfab4284661e586f6236a1e9f3ef61533f0a8836445d130aa9a97f86d3be8c9df9e16408a3d7e621c16953a079bcd0b7fcf109ce926877857a5ee29d543706e3d159418fa079a31f02e0ce286f2c315f2fbd8da612d38c79373016065b02cec1e54a38034748ff196eee8cab11750d032d07aa5a175a5862e74af995902accfac36da585f9ce2589566e42e62af9c933f7b44ea3b761bda0fea2b7b6ddf85e4ffa9179f1ffb2da5757f4ab62d0f79d5c7bec672230e373882dec0be091824790bebdaebbd47438315f137d7f88f241bc4f307
#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(70609);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2015/11/17");

  script_cve_id("CVE-2013-5135", "CVE-2013-5136", "CVE-2013-5229");
  script_bugtraq_id(63284, 63286);
  script_osvdb_id(98869, 98891, 130246);
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2013-10-22-6");
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2013-10-22-7");

  script_name(english:"Apple Remote Desktop < 3.5.4 / 3.7 Multiple Vulnerabilities (Mac OS X)");
  script_summary(english:"Reads version from Info.plist");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The Mac OS X host has a remote management application that is
potentially affected by multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its version, the Apple Remote Desktop install on the
remote host is earlier than 3.5.4 / 3.7.  As such, it is potentially
affected the following vulnerabilities :

  - A format string vulnerability exists in Remote 
    Desktop's handling of a VNC username. (CVE-2013-5135)

  - An information disclosure vulnerability exists because
    Remote Desktop may use password authentication without
    warning that the connection would be encrypted if a
    third-party VNC server supports certain authentication
    types. Note that this does not affect installs of
    version 3.5.x or earlier. (CVE_2013-5136)

  - An authentication bypass vulnerability exists due to a
    flaw in the full-screen feature that is triggered when
    handling text entered in the dialog box upon recovering 
    from sleep mode with a remote connection alive. A local
    attacker can exploit this to bypass intended access
    restrictions. (CVE-2013-5229)");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT5997");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT5998");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2013/Oct/msg00007.html");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2013/Oct/msg00008.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Apple Remote Desktop 3.5.4 / 3.7 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:apple_remote_desktop");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("macosx_func.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/MacOSX/Version"))audit(AUDIT_HOST_NOT, "running Mac OS X");

plist = '/System/Library/CoreServices/RemoteManagement/AppleVNCServer.bundle/Contents/Info.plist';
cmd =  'plutil -convert xml1 -o - \'' + plist + '\' | ' +
  'grep -A 1 CFBundleShortVersionString | ' +
  'tail -n 1 | ' +
  'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\'';
version = exec_cmd(cmd:cmd);
if (!strlen(version)) audit(AUDIT_NOT_INST, "Apple Remote Desktop Client");

if (version !~ "^[0-9]") exit(1, "The version does not look valid (" + version + ").");


if (
  ereg(pattern:"^3\.[0-4]($|[^0-9])", string:version) ||
  ereg(pattern:"^3\.5\.[0-3]($|[^0-9])", string:version) ||
  ereg(pattern:"^3\.6(\.[0-9])?($|[^0-9.])", string:version)
)
{
  if (report_verbosity > 0)
  {
    report = 
      '\n  Installed version : ' + version + 
      '\n  Fixed version     : 3.5.4 / 3.7' +
      '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, "Apple Remote Desktop Client", version);
