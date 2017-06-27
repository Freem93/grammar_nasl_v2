#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(89738);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/11/29 20:13:37 $");

  script_cve_id(
    "CVE-2009-0798",
    "CVE-2009-1888",
    "CVE-2009-2813",
    "CVE-2009-2906",
    "CVE-2009-2948"
  );
  script_bugtraq_id(
    34692,
    36363,
    36572,
    36573
  );
  script_osvdb_id(
    54299,
    55411,
    57955,
    58519,
    58520
  );
  script_xref(name:"VMSA", value:"2010-0006");

  script_name(english:"VMware ESX Third-Party Libraries and Components Multiple Vulnerabilities (VMSA-2010-0006) (remote check)");
  script_summary(english:"Checks the ESX / ESXi version and build number.");

  script_set_attribute(attribute:"synopsis", value:
"The remote VMware ESX host is missing a security-related patch.");
  script_set_attribute(attribute:"description", value:
"The remote VMware ESX host is missing a security-related patch. It is,
therefore, affected by multiple vulnerabilities in several third-party
components and libraries :

  - A denial of service vulnerability exists in the ACPI
    Event Daemon (acpid) that allows a remote attacker to
    cause a consumption of CPU resources by opening a large
    number of UNIX sockets without closing them.
    (CVE-2009-0798)

  - A security bypass vulnerability exists in Samba in the
    acl_group_override() function when dos filemode is
    enabled. A remote attacker can exploit this to modify
    access control lists for files via vectors related to
    read access to uninitialized memory. (CVE-2009-1888)

  - A security bypass vulnerability exists in Samba in the
    SMB subsystem due to improper handling of errors when
    resolving pathnames. An authenticated, remote attacker
    can exploit this to bypass intended sharing
    restrictions, and read, create, or modify files, in
    certain circumstances involving user accounts that lack
    home directories. (CVE-2009-2813)

  - A denial of service vulnerability exists in Samba that
    allows authenticated, remote attackers to cause an
    infinite loop via an unanticipated oplock break
    notification reply packet. (CVE-2009-2906)

  - An information disclosure vulnerability exists in Samba
    in mount.cifs due to improper enforcement of
    permissions. A local attacker can exploit this to read
    part of the credentials file and obtain the password by
    specifying the path to the credentials file and using
    the --verbose or -v option. (CVE-2009-2948)");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2010-0006");
  script_set_attribute(attribute:"see_also", value:"http://lists.vmware.com/pipermail/security-announce/2011/000123.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the vendor advisory that
pertains to ESX version 4.0.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(264, 399);

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/04/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/04/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
  script_family(english:"VMware ESX Local Security Checks");

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
          "4.0", "244038"
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
  security_report_v4(port:port, extra:report, severity:SECURITY_WARNING);
  exit(0);
}
else
  audit(AUDIT_INST_VER_NOT_VULN, "VMware " + esx, ver, build);
