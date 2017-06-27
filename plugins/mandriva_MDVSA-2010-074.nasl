#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2010:074. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(45548);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2014/12/22 14:20:01 $");

  script_cve_id("CVE-2010-0436");
  script_bugtraq_id(39467);
  script_xref(name:"MDVSA", value:"2010:074");

  script_name(english:"Mandriva Linux Security Advisory : kdebase (MDVSA-2010:074)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Mandriva Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A vulnerability has been found and corrected in kdm
(kdebase/kdebase4-workspace) :

KDM contains a race condition that allows local attackers to make
arbitrary files on the system world-writeable. This can happen while
KDM tries to create its control socket during user login. This
vulnerability has been discovered by Sebastian Krahmer from the SUSE
Security Team (CVE-2010-0436).

It is adviced to reboot the computer after applying the updated
packages in order to the security fix to take full effect.

Packages for 2008.0 are provided for Corporate Desktop 2008.0
customers.

The updated packages have been patched to correct this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.kde.org/info/security/advisory-20100413-1.txt"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdebase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdebase-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdebase-devel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdebase-kate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdebase-kdeprintfax");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdebase-kdm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdebase-kmenuedit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdebase-konsole");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdebase-ksysguard");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdebase-nsplugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdebase-progs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdebase-session-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdebase4-workspace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdebase4-workspace-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kdebase4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kdebase4-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kdebase4-kate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kdecorations4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kephal4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kfontinst4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kfontinstui4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64khotkeysprivate4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kscreensaver5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64ksgrd4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kwineffects1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kwinnvidiahack4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kworkspace4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64lsofui4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64nepomukquery4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64nepomukqueryclient4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64plasma-geolocation-interface4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64plasma_applet_system_monitor4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64plasmaclock4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64polkitkdeprivate4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64processcore4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64processui4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64solidcontrol4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64solidcontrolifaces4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64taskmanager4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64time_solar4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64weather_ion4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkdebase4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkdebase4-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkdebase4-kate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkdecorations4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkephal4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkfontinst4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkfontinstui4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkhotkeysprivate4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkscreensaver5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libksgrd4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkwineffects1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkwinnvidiahack4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkworkspace4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:liblsofui4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libnepomukquery4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libnepomukqueryclient4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libplasma-geolocation-interface4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libplasma_applet_system_monitor4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libplasmaclock4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libpolkitkdeprivate4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libprocesscore4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libprocessui4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libsolidcontrol4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libsolidcontrolifaces4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libtaskmanager4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libtime_solar4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libweather_ion4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:plasma-applet-battery");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:plasma-applet-calendar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:plasma-applet-quicklaunch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:plasma-applet-system-monitor-cpu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:plasma-applet-system-monitor-hdd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:plasma-applet-system-monitor-hwinfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:plasma-applet-system-monitor-net");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:plasma-applet-system-monitor-temperature");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:plasma-applet-webbrowser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:plasma-krunner-powerdevil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:plasma-runner-places");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:policykit-kde");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2008.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2009.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2010.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/04/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/04/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");
  script_family(english:"Mandriva Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/Mandrake/release", "Host/Mandrake/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Mandrake/release")) audit(AUDIT_OS_NOT, "Mandriva / Mandake Linux");
if (!get_kb_item("Host/Mandrake/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^(amd64|i[3-6]86|x86_64)$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Mandriva / Mandrake Linux", cpu);


flag = 0;
if (rpm_check(release:"MDK2008.0", reference:"kdebase-3.5.10-0.4mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdebase-common-3.5.10-0.4mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdebase-devel-doc-3.5.10-0.4mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdebase-kate-3.5.10-0.4mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdebase-kdeprintfax-3.5.10-0.4mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdebase-kdm-3.5.10-0.4mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdebase-kmenuedit-3.5.10-0.4mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdebase-konsole-3.5.10-0.4mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdebase-ksysguard-3.5.10-0.4mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdebase-nsplugins-3.5.10-0.4mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdebase-progs-3.5.10-0.4mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kdebase-session-plugins-3.5.10-0.4mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64kdebase4-3.5.10-0.4mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64kdebase4-devel-3.5.10-0.4mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64kdebase4-kate-3.5.10-0.4mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libkdebase4-3.5.10-0.4mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libkdebase4-devel-3.5.10-0.4mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libkdebase4-kate-3.5.10-0.4mdv2008.0", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2009.1", reference:"kdebase4-workspace-4.2.4-1.7mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"kdebase4-workspace-devel-4.2.4-1.7mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"kdm-4.2.4-1.7mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"x86_64", reference:"lib64kdecorations4-4.2.4-1.7mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"x86_64", reference:"lib64kephal4-4.2.4-1.7mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"x86_64", reference:"lib64kfontinst4-4.2.4-1.7mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"x86_64", reference:"lib64kfontinstui4-4.2.4-1.7mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"x86_64", reference:"lib64khotkeysprivate4-4.2.4-1.7mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"x86_64", reference:"lib64kscreensaver5-4.2.4-1.7mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"x86_64", reference:"lib64ksgrd4-4.2.4-1.7mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"x86_64", reference:"lib64kwineffects1-4.2.4-1.7mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"x86_64", reference:"lib64kwinnvidiahack4-4.2.4-1.7mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"x86_64", reference:"lib64kworkspace4-4.2.4-1.7mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"x86_64", reference:"lib64lsofui4-4.2.4-1.7mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"x86_64", reference:"lib64nepomukquery4-4.2.4-1.7mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"x86_64", reference:"lib64nepomukqueryclient4-4.2.4-1.7mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"x86_64", reference:"lib64plasma_applet_system_monitor4-4.2.4-1.7mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"x86_64", reference:"lib64plasmaclock4-4.2.4-1.7mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"x86_64", reference:"lib64processcore4-4.2.4-1.7mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"x86_64", reference:"lib64processui4-4.2.4-1.7mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"x86_64", reference:"lib64solidcontrol4-4.2.4-1.7mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"x86_64", reference:"lib64solidcontrolifaces4-4.2.4-1.7mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"x86_64", reference:"lib64taskmanager4-4.2.4-1.7mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"x86_64", reference:"lib64weather_ion4-4.2.4-1.7mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"libkdecorations4-4.2.4-1.7mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"libkephal4-4.2.4-1.7mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"libkfontinst4-4.2.4-1.7mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"libkfontinstui4-4.2.4-1.7mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"libkhotkeysprivate4-4.2.4-1.7mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"libkscreensaver5-4.2.4-1.7mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"libksgrd4-4.2.4-1.7mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"libkwineffects1-4.2.4-1.7mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"libkwinnvidiahack4-4.2.4-1.7mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"libkworkspace4-4.2.4-1.7mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"liblsofui4-4.2.4-1.7mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"libnepomukquery4-4.2.4-1.7mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"libnepomukqueryclient4-4.2.4-1.7mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"libplasma_applet_system_monitor4-4.2.4-1.7mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"libplasmaclock4-4.2.4-1.7mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"libprocesscore4-4.2.4-1.7mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"libprocessui4-4.2.4-1.7mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"libsolidcontrol4-4.2.4-1.7mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"libsolidcontrolifaces4-4.2.4-1.7mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"libtaskmanager4-4.2.4-1.7mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"libweather_ion4-4.2.4-1.7mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"plasma-applet-battery-4.2.4-1.7mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"plasma-applet-calendar-4.2.4-1.7mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"plasma-applet-quicklaunch-4.2.4-1.7mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"plasma-applet-system-monitor-cpu-4.2.4-1.7mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"plasma-applet-system-monitor-hdd-4.2.4-1.7mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"plasma-applet-system-monitor-hwinfo-4.2.4-1.7mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"plasma-applet-system-monitor-net-4.2.4-1.7mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"plasma-applet-system-monitor-temperature-4.2.4-1.7mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"plasma-applet-webbrowser-4.2.4-1.7mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"plasma-krunner-powerdevil-4.2.4-1.7mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"plasma-runner-places-4.2.4-1.7mdv2009.1", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2010.0", reference:"kdebase4-workspace-4.3.5-0.11mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"kdebase4-workspace-devel-4.3.5-0.11mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"kdm-4.3.5-0.11mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64kdecorations4-4.3.5-0.11mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64kephal4-4.3.5-0.11mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64kfontinst4-4.3.5-0.11mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64kfontinstui4-4.3.5-0.11mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64khotkeysprivate4-4.3.5-0.11mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64kscreensaver5-4.3.5-0.11mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64ksgrd4-4.3.5-0.11mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64kwineffects1-4.3.5-0.11mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64kwinnvidiahack4-4.3.5-0.11mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64kworkspace4-4.3.5-0.11mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64lsofui4-4.3.5-0.11mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64nepomukquery4-4.3.5-0.11mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64nepomukqueryclient4-4.3.5-0.11mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64plasma-geolocation-interface4-4.3.5-0.11mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64plasma_applet_system_monitor4-4.3.5-0.11mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64plasmaclock4-4.3.5-0.11mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64polkitkdeprivate4-4.3.5-0.11mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64processcore4-4.3.5-0.11mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64processui4-4.3.5-0.11mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64solidcontrol4-4.3.5-0.11mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64solidcontrolifaces4-4.3.5-0.11mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64taskmanager4-4.3.5-0.11mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64time_solar4-4.3.5-0.11mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64weather_ion4-4.3.5-0.11mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libkdecorations4-4.3.5-0.11mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libkephal4-4.3.5-0.11mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libkfontinst4-4.3.5-0.11mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libkfontinstui4-4.3.5-0.11mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libkhotkeysprivate4-4.3.5-0.11mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libkscreensaver5-4.3.5-0.11mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libksgrd4-4.3.5-0.11mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libkwineffects1-4.3.5-0.11mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libkwinnvidiahack4-4.3.5-0.11mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libkworkspace4-4.3.5-0.11mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"liblsofui4-4.3.5-0.11mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libnepomukquery4-4.3.5-0.11mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libnepomukqueryclient4-4.3.5-0.11mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libplasma-geolocation-interface4-4.3.5-0.11mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libplasma_applet_system_monitor4-4.3.5-0.11mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libplasmaclock4-4.3.5-0.11mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libpolkitkdeprivate4-4.3.5-0.11mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libprocesscore4-4.3.5-0.11mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libprocessui4-4.3.5-0.11mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libsolidcontrol4-4.3.5-0.11mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libsolidcontrolifaces4-4.3.5-0.11mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libtaskmanager4-4.3.5-0.11mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libtime_solar4-4.3.5-0.11mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libweather_ion4-4.3.5-0.11mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"plasma-applet-battery-4.3.5-0.11mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"plasma-applet-calendar-4.3.5-0.11mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"plasma-applet-quicklaunch-4.3.5-0.11mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"plasma-applet-system-monitor-cpu-4.3.5-0.11mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"plasma-applet-system-monitor-hdd-4.3.5-0.11mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"plasma-applet-system-monitor-hwinfo-4.3.5-0.11mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"plasma-applet-system-monitor-net-4.3.5-0.11mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"plasma-applet-system-monitor-temperature-4.3.5-0.11mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"plasma-applet-webbrowser-4.3.5-0.11mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"plasma-krunner-powerdevil-4.3.5-0.11mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"plasma-runner-places-4.3.5-0.11mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"policykit-kde-4.3.5-0.11mdv2010.0", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
