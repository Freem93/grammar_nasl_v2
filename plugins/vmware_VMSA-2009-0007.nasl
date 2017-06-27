#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from VMware Security Advisory 2009-0007. 
# The text itself is copyright (C) VMware Inc.
#

include("compat.inc");

if (description)
{
  script_id(40392);
  script_version("$Revision: 1.21 $");
  script_cvs_date("$Date: 2016/11/29 20:13:37 $");

  script_cve_id("CVE-2008-1382", "CVE-2009-0040", "CVE-2009-1805");
  script_bugtraq_id(28770, 33827);
  script_osvdb_id(44364, 53315, 53316, 53317, 54922);
  script_xref(name:"VMSA", value:"2009-0007");

  script_name(english:"VMSA-2009-0007 : VMware Hosted products and ESX and ESXi patches resolve security issues");
  script_summary(english:"Checks esxupdate output for the patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote VMware ESX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"a. VMware Descheduled Time Accounting driver vulnerability may cause a
   denial of service in Windows based virtual machines.

   The VMware Descheduled Time Accounting Service is an optional,
   experimental service that provides improved guest operating system
   accounting.

   This patch fixes a denial of service vulnerability that could be
   triggered in a virtual machine by an unprivileged, locally
   logged-on user in the virtual machine.

   Virtual machines are affected under the following conditions :

   - The virtual machine is running a Windows operating system.

   - The VMware Descheduled Time Accounting driver is installed
     in the virtual machine. Note that this is an optional (non-
     default) part of the VMware Tools installation.

   - The VMware Descheduled Time Accounting Service is not running
     in the virtual machine

   The VMware Descheduled Time Accounting Service is no longer provided
   in newer versions of VMware Tools, starting with the versions
   released in Fusion 2.0.2 and ESX 4.0.

   However, virtual machines migrated from vulnerable releases will
   still be vulnerable if the three conditions listed above are met,
   until their tools are upgraded.

   Steps needed to remediate this vulnerability :

   Guest systems on VMware Workstation, Player, ACE, Server, Fusion
    - Install the new version of Workstation, Player, ACE, Server,
      Fusion (see below for version information)
    - Upgrade tools in the virtual machine (virtual machine users
      will be prompted to upgrade).

   Guest systems on ESX 3.5, ESXi 3.5, ESX 3.0.2, ESX 3.0.3
    - Install the relevant patches (see below for patch identifiers)
    - Manually upgrade tools in the virtual machine (virtual machine
      users will not be prompted to upgrade).  Note the VI Client will
      not show the VMware tools is out of date in the summary tab.
      Please see http://tinyurl.com/27mpjo page 80 for details.

   Guests systems on ESX 4.0 and ESXi 4.0 that have been migrated from
   ESX 3.5, ESXi 3.5, and ESX 3.0.x
    - Install/upgrade the new tools in the virtual machine (virtual
      machine users will be prompted to upgrade).

   If the Descheduled Time Accounting driver was installed, the tools
   upgrade will result in an updated driver for Workstation, Player,
   ACE, Server, ESX 3.0.2, ESX 3.0.3, ESX 3.5, ESXi 3.5. For Fusion,
   ESX 4.0, and ESXi 4.0 the tools upgrade will result in the removal
   of the driver.

   VMware would like to thank Nikita Tarakanov for reporting this
   issue to us.

   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the name CVE-2009-1805 to this issue.

b. Updated libpng package for the ESX 2.5.5 Service Console

   The libpng packages contain a library of functions for creating and
   manipulating PNG (Portable Network Graphics) image format files.

   A flaw was discovered in libpng that could result in libpng trying
   to free() random memory if certain, unlikely error conditions
   occurred. If a carefully-crafted PNG file was loaded by an
   application linked against libpng, it could cause the application
   to crash or, potentially, execute arbitrary code with the
   privileges of the user running the application.

   A flaw was discovered in the way libpng handled PNG images
   containing 'unknown' chunks. If an application linked against libpng
   attempted to process a malformed, unknown chunk in a malicious PNG
   image, it could cause the application to crash.

   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the names CVE-2009-0040 and CVE-2008-1382 to these
   issues.

   The VMware version number of libpng after applying the update is
   libpng-1.0.14-12.i386.rpm."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.vmware.com/pipermail/security-announce/2009/000057.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply the missing patch.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(94, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:2.5.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:3.0.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:3.0.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/05/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/07/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
  script_family(english:"VMware ESX Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/VMware/release", "Host/VMware/version");
  script_require_ports("Host/VMware/esxupdate", "Host/VMware/esxcli_software_vibs");

  exit(0);
}


include("audit.inc");
include("vmware_esx_packages.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/VMware/release")) audit(AUDIT_OS_NOT, "VMware ESX / ESXi");
if (
  !get_kb_item("Host/VMware/esxcli_software_vibs") &&
  !get_kb_item("Host/VMware/esxupdate")
) audit(AUDIT_PACKAGE_LIST_MISSING);


init_esx_check(date:"2009-05-28");
flag = 0;


if (esx_check(ver:"ESX 2.5.5", patch:"13")) flag++;

if (esx_check(ver:"ESX 3.0.2", patch:"ESX-1008420")) flag++;

if (
  esx_check(
    ver           : "ESX 3.0.3",
    patch         : "ESX303-200905401-SG",
    patch_updates : make_list("ESX303-201002203-UG", "ESX303-Update01")
  )
) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:esx_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
