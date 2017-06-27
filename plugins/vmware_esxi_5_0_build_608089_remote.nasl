#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70881);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/08/16 14:42:21 $");

  script_cve_id(
    "CVE-2009-3560",
    "CVE-2009-3720",
    "CVE-2010-0405",
    "CVE-2010-1634",
    "CVE-2010-2089",
    "CVE-2011-1521",
    "CVE-2012-1518"
  );
  script_bugtraq_id(
    36097,
    37203,
    40370,
    40863,
    43331,
    47024,
    53006
  );
  script_osvdb_id(
    59737,
    60797,
    64957,
    65151,
    68167,
    71330,
    81163
  );
  script_xref(name:"VMSA", value:"2012-0001");
  script_xref(name:"IAVB", value:"2010-B-0083");
  script_xref(name:"VMSA", value:"2012-0005");
  script_xref(name:"VMSA", value:"2012-0007");
  script_xref(name:"EDB-ID", value:"34145");

  script_name(english:"ESXi 5.0 < Build 608089 Multiple Vulnerabilities (remote check)");
  script_summary(english:"Checks the ESXi version and build number.");

  script_set_attribute(attribute:"synopsis", value:
"The remote VMware ESXi 5.0 host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote VMware ESXi 5.0 host is affected by multiple
vulnerabilities :

  - A denial of service vulnerability exists in the
    big2_toUtf8() function in file lib/xmltok.c in the
    libexpat library. A remote attacker can exploit this,
    via an XML document having malformed UTF-8 sequences, to
    cause a buffer over-read, thus crashing the application.
    (CVE-2009-3560)

  - A denial of service vulnerability exists in the
    updatePosition() function in file lib/xmltok.c in the
    libexpat library. A remote attacker can exploit this,
    via an XML document having malformed UTF-8 sequences, to
    cause a buffer over-read, thus crashing the application.
    (CVE-2009-3720)

  - An integer overflow condition exists in the
    BZ2_decompress() function in file decompress.c in the
    bzip2 and libbzip2 library. A remote attacker can
    exploit this, via a crafted compressed file, to cause
    a denial of service or the execution of arbitrary code.
    (CVE-2010-0405)

  - A denial of service vulnerability exists in the audioop
    module due to multiple integer overflows conditions in
    file audioop.c. A remote attacker can exploit this, via
    a large fragment or argument, to cause a buffer
    overflow, resulting in an application crash.
    (CVE-2010-1634)

  - A denial of service vulnerability exists in the audioop
    module due to a failure to verify the relationships
    between size arguments and byte string length. A remote
    attacker can exploit this, via crafted arguments, to
    cause memory corruption, resulting in an application
    crash. (CVE-2010-2089)

  - A flaw exists in the urllib and urllib2 modules due to
    processing Location headers that specify redirection to
    a file. A remote attacker can exploit this, via a
    crafted URL, to gain sensitive information or cause a
    denial of service. (CVE-2011-1521)

  - A privilege escalation vulnerability exists due to an
    incorrect ACL being used for the VMware Tools folder. An
    attacker on an adjacent network with access to a guest
    operating system can exploit this to gain elevated
    privileges on the guest operating system.
    (CVE-2012-1518)");
  script_set_attribute(attribute:"see_also", value:"http://kb.vmware.com/kb/2011432");
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2012-0001.html");
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2012-0005.html");
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2012-0007.html");
  script_set_attribute(attribute:"see_also", value:"http://kb.vmware.com/kb/2010823");
  script_set_attribute(attribute:"see_also", value:"http://kb.vmware.com/kb/2011433");
  script_set_attribute(attribute:"solution", value:
"Apply patches ESXi500-201203102-SG and ESXi500-201203101-SG according
to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'White_Phosphorus');
  script_cwe_id(119);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/11/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:5.0");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("vmware_vsphere_detect.nbin");
  script_require_keys("Host/VMware/version", "Host/VMware/release");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

ver = get_kb_item_or_exit("Host/VMware/version");
rel = get_kb_item_or_exit("Host/VMware/release");

if ("ESXi" >!< rel) audit(AUDIT_OS_NOT, "ESXi");
if ("VMware ESXi 5.0" >!< rel) audit(AUDIT_OS_NOT, "ESXi 5.0");

match = eregmatch(pattern:'^VMware ESXi.*build-([0-9]+)$', string:rel);
if (isnull(match)) exit(1, 'Failed to extract the ESXi build number.');

build = int(match[1]);
fixed_build = 608089;

if (build < fixed_build)
{
  if (report_verbosity > 0)
  {
    report = '\n  ESXi version    : ' + ver +
             '\n  Installed build : ' + build +
             '\n  Fixed build     : ' + fixed_build +
             '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else exit(0, "The host has "+ver+" build "+build+" and thus is not affected.");
