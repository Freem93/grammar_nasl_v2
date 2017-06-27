#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(41971);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/11/28 21:06:38 $");

  script_cve_id("CVE-2009-3281", "CVE-2009-3282");
  script_bugtraq_id(36578, 36579);
  script_osvdb_id(58475, 58476);

  script_name(english:"VMware Fusion < 2.0.6 (VMSA-2009-0013)");
  script_summary(english:"Checks version Fusion");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has an application that is affected by two security
issues."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of VMware Fusion installed on the Mac OS X host is earlier
than 2.0.6.  Such versions are affected by two security issues :

  - A vulnerability in the vmx86 kernel extension allows
    an unprivileged userland program to initialize
    several function pointers via the '0x802E564A' IOCTL
    code, which can lead to arbitrary code execution in
    the kernel context. (CVE-2009-3281)

  - An integer overflow in the vmx86 kernel extension allows
    for a denial of service of the host by an unprivileged 
    local user. (CVE-2009-3282)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.vmware.com/pipermail/security-announce/2009/000066.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.securityfocus.com/advisories/18019"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.securityfocus.com/archive/1/506891"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.securityfocus.com/archive/1/506893"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to VMware Fusion 2.0.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(189, 264);
  script_set_attribute(attribute:"vuln_publication_date", value:"2009/10/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/10/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/10/02");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:fusion");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("macosx_fusion_detect.nasl");
  script_require_keys("MacOSX/Fusion/Version");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");


version = get_kb_item_or_exit("MacOSX/Fusion/Version");
fixed_version = "2.0.6";

if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report = 
      '\n  Installed version : ' + version + 
      '\n  Fixed version     : ' + fixed_version + '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else exit(0, "The remote host is not affected since VMware Fusion "+version+" is installed.");
