#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(51079);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2011/12/12 17:42:01 $");

  script_cve_id("CVE-2010-4295", "CVE-2010-4296", "CVE-2010-4297");
  script_bugtraq_id(45167, 45166, 45168);
  script_osvdb_id(69584, 69585, 69590);
  script_xref(name:"IAVA", value:"2010-A-0168");

  script_name(english:"VMware Fusion < 3.1.2 (VMSA-2010-0018)");
  script_summary(english:"Checks version of Fusion");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has an application that is affected by three security
issues."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of VMware Fusion installed on the Mac OS X host is
earlier than 3.1.2.  Such versions are affected by three security
issues :

  - A race condition in the mounting process in vmware-mount
    in allows host OS users to gain privileges via vectors 
    involving temporary files. (CVE-2010-4295)

  - The VMware Tools update functionality allows host OS 
    users to gain privileges on the guest OS via unspecified
    vectors, related to a 'command injection' issue. 
    (CVE-2010-4297)
  
  - vmware-mount does not properly load libraries, which 
    allows host OS users to gain privileges via vectors 
    involving shared object files. (CVE-2010-4296)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.vmware.com/security/advisories/VMSA-2010-0018.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.vmware.com/pipermail/security-announce/2010/000112.html"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to VMware Fusion 3.1.2 or later.");
 script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/12/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/12/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/12/08");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:fusion");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2010-2011 Tenable Network Security, Inc.");

  script_dependencies("macosx_fusion_detect.nasl");
  script_require_keys("MacOSX/Fusion/Version");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("MacOSX/Fusion/Version");
fixed_version = "3.1.2";

major = split(version, sep:'.', keep:FALSE);
major = major[0];

if(major == "3")
{
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
    exit(0);
  }
  else exit(0, "The host is not affected since VMware Fusion "+version+" is installed.");
}
else exit(0, "The host is not affected since VMware Fusion "+version+" is installed and this plugin looks only at versions "+major+".x.");
