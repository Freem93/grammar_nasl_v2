#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(89678);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/05/19 18:10:50 $");

  script_cve_id(
    "CVE-2009-3080",
    "CVE-2009-4536",
    "CVE-2010-1188",
    "CVE-2010-2240",
    "CVE-2011-1787",
    "CVE-2011-2145",
    "CVE-2011-2146",
    "CVE-2011-2217"
  );
  script_bugtraq_id(
    37068,
    37519,
    39016,
    42505,
    48098,
    48099
  );
  script_osvdb_id(
    60311,
    61769,
    63453,
    67237,
    73211,
    73240,
    73241,
    73242
  );
  script_xref(name:"VMSA", value:"2011-0009");

  script_name(english:"VMware ESX / ESXi Multiple Vulnerabilities (VMSA-2011-0009) (remote check)");
  script_summary(english:"Checks the ESX / ESXi version and build number.");

  script_set_attribute(attribute:"synopsis", value:
"The remote VMware ESX / ESXi host is missing a security-related patch.");
  script_set_attribute(attribute:"description", value:
"The remote VMware ESX / ESXi host is missing a security-related patch.
It is, therefore, affected by multiple vulnerabilities :

  - A flaw exists in the Linux Kernel in the
    do_anonymous_page() function due to improper separation
    of the stack and the heap. An attacker can exploit this
    to execute arbitrary code. (CVE-2010-2240)

  - A packet filter bypass exists in the Linux Kernel e1000
    driver due to processing trailing payload data as a
    complete frame. A remote attacker can exploit this to
    bypass packet filters via a large packet with a crafted
    payload. (CVE-2009-4536)

  - A use-after-free error exists in the Linux Kernel when
    IPV6_RECVPKTINFO is set on a listening socket. A remote
    attacker can exploit this, via a SYN packet while the
    socket is in a listening (TCP_LISTEN) state, to cause a
    kernel panic, resulting in a denial of service
    condition. (CVE-2010-1188)

  - An array index error exists in the Linux Kernel in the
    gdth_read_event() function. A local attacker can exploit
    this, via a negative event index in an IOCTL request, to
    cause a denial of service condition. (CVE-2009-3080)

  - A race condition exists in the VMware Host Guest File
    System (HGFS) that allows guest operating system users
    to gain privileges by mounting a filesystem on top of an
    arbitrary directory. (CVE-2011-1787)

  - A flaw exists in the VMware Host Guest File System
    (HGFS) that allows a Solaris or FreeBSD guest operating
    system user to modify arbitrary guest operating system
    files. (CVE-2011-2145)

  - A flaw exists in the VMware Host Guest File System
    (HGFS) that allows guest operating system users to
    disclose host operating system files and directories.
    (CVE-2011-2146)

  - A flaw exists in the bundled Tom Sawyer GET Extension
    Factory that allows a remote attacker to cause a denial
    of service condition or the execution of arbitrary code
    via a crafted HTML document. (CVE-2011-2217)");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2011-0009");
  script_set_attribute(attribute:"see_also", value:"http://lists.vmware.com/pipermail/security-announce/2011/000158.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the vendor advisory that
pertains to ESX version 3.5 / 4.0 / 4.1 or ESXi version 3.5 / 4.0 /
4.1 / 5.0.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Tom Sawyer Software GET Extension Factory Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/10/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/06/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
  script_family(english:"Misc.");

  script_dependencies("vmware_vsphere_detect.nbin");
  script_require_keys("Host/VMware/version", "Host/VMware/release");
  script_require_ports("Host/VMware/vsphere");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

ver = get_kb_item_or_exit("Host/VMware/version");
rel = get_kb_item_or_exit("Host/VMware/release");
port = get_kb_item_or_exit("Host/VMware/vsphere");
esx = '';

if ("ESX" >!< rel)
  audit(AUDIT_OS_NOT, "VMware ESX/ESXi");

extract = eregmatch(pattern:"^(ESXi?) (\d\.\d).*$", string:ver);
if (isnull(extract))
  audit(AUDIT_UNKNOWN_APP_VER, "VMware ESX/ESXi");
else
{
  esx = extract[1];
  ver = extract[2];
}

# fixed build numbers are the same for ESX and ESXi
fixes = make_array(
          "3.5", "391406",
          "4.0", "392990",
          "4.1", "381591",
          "5.0", "515841"
        );

fix = FALSE;
fix = fixes[ver];

# get the build before checking the fix for the most complete audit trail
extract = eregmatch(pattern:'^VMware ESXi?.* build-([0-9]+)$', string:rel);
if (isnull(extract))
  audit(AUDIT_UNKNOWN_BUILD, "VMware " + esx, ver);

build = int(extract[1]);

# if there is no fix in the array, fix is FALSE
if (!fix)
  audit(AUDIT_INST_VER_NOT_VULN, "VMware " + esx, ver, build);

if (build < fix)
{

  report = '\n  Version         : ' + esx + " " + ver +
           '\n  Installed build : ' + build +
           '\n  Fixed build     : ' + fix +
           '\n';

  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
  exit(0);
}
else
  audit(AUDIT_INST_VER_NOT_VULN, "VMware " + esx, ver, build);
