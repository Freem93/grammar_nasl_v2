#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(61297);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2014/08/16 19:47:27 $");

  script_cve_id("CVE-2012-1182");

  script_name(english:"Scientific Linux Security Update : samba3x on SL5.x i386/x86_64");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Scientific Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Samba is an open source implementation of the Server Message Block
(SMB) or Common Internet File System (CIFS) protocol, which allows
PC-compatible machines to share files, printers, and other
information.

A flaw in the Samba suite's Perl-based DCE/RPC IDL (PIDL) compiler,
used to generate code to handle RPC calls, resulted in multiple buffer
overflows in Samba. A remote, unauthenticated attacker could send a
specially crafted RPC request that would cause the Samba daemon (smbd)
to crash or, possibly, execute arbitrary code with the privileges of
the root user. (CVE-2012-1182)

Users of Samba are advised to upgrade to these updated packages, which
contain a backported patch to resolve this issue. After installing
this update, the smb service will be restarted automatically."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1204&L=scientific-linux-errata&T=0&P=565
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?eda6425c"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Samba SetInformationPolicy AuditEventsInfo Heap Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");
  script_family(english:"Scientific Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Scientific Linux " >!< release) audit(AUDIT_HOST_NOT, "running Scientific Linux");
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL5", reference:"samba3x-3.5.10-0.108.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"samba3x-client-3.5.10-0.108.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"samba3x-common-3.5.10-0.108.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"samba3x-debuginfo-3.5.10-0.108.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"samba3x-doc-3.5.10-0.108.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"samba3x-domainjoin-gui-3.5.10-0.108.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"samba3x-swat-3.5.10-0.108.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"samba3x-winbind-3.5.10-0.108.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"samba3x-winbind-devel-3.5.10-0.108.el5_8")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
