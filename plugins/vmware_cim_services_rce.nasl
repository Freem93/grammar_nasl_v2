#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70448);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/10/16 00:12:50 $");

  script_cve_id("CVE-2013-3657", "CVE-2013-3658");
  script_bugtraq_id(62316, 62323);
  script_osvdb_id(97087, 97088);

  script_name(english:"VMware ESX/ESXi CIM Services Multiple Vulnerabilities");
  script_summary(english:"Checks patch level of ESX/ESXi");

  script_set_attribute(attribute:"synopsis", value:
"The remote VMware ESXi / ESX host is missing a security-related
patch.");
  script_set_attribute(attribute:"description", value:
"The remote VMware ESXi / ESX host is potentially affected by the
following vulnerabilities :

  - A buffer overflow flaw exists that allows remote,
    authenticated attackers to execute arbitrary code.
    (CVE-2013-3657)

  - A directory traversal flaw exists that allows remote
    attackers to delete arbitrary files. (CVE-2013-3658)

Note that the vendor has not publicly acknowledged these flaws.");
  # http://blog.shanonolsson.com/blog/2013/08/24/esxi-cim-services-authentication-bypass-and-remote-code-execution-vulnerabilities/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?87d7627e");
  script_set_attribute(attribute:"solution", value:
"The vendor reportedly has silently patched these issues in the
following releases :

  - ESX/ESXi 4.0: Patch 201203401
  - ESX/ESXi 4.1: Patch 201201401
  - ESXi     5.0: Patch 201203101");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/08/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:4.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:5.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"VMware ESX Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/VMware/release", "Host/VMware/version", "Host/VMware/esxupdate");

  exit(0);
}

include("audit.inc");
include("vmware_esx_packages.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/VMware/release")) audit(AUDIT_OS_NOT, 'VMware ESX / ESXi');
if (!get_kb_item("Host/VMware/esxupdate")) audit(AUDIT_PACKAGE_LIST_MISSING);

init_esx_check(date:"2012-03-29");
flag = 0;

if (esx_check(ver:"ESX 4.0", patch:"ESX400-201203401-SG")) flag++;
if (esx_check(ver:"ESX 4.1", patch:"ESX410-201201401-SG")) flag++;
if (esx_check(ver:"ESXi 4.0", vib:"VMware:vmware-esx-firmware:4.0.0-4.11.660575")) flag++;
if (esx_check(ver:"ESXi 4.1", vib:"VMware:vmware-esx-firmware:4.1.0-2.18.582267")) flag++;
if (esx_check(ver:"ESXi 5.0", vib:"VMware:esx-base:5.0.0-1.11.623860")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:esx_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, 'affected');
