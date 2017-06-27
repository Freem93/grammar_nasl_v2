#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2007-4778.
#

include("compat.inc");

if (description)
{
  script_id(29795);
  script_version ("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/10/21 22:04:02 $");

  script_xref(name:"FEDORA", value:"2007-4778");

  script_name(english:"Fedora 8 : gallery2-2.2.4-1.fc8 (2007-4778)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Gallery 2.2.4 addresses the following security vulnerabilities :

  - Publish XP module - Fixed unauthorized album creation
    and file uploads.

    - URL rewrite module - Fixed local file inclusion
      vulnerability in unsecured admin controller and
      information disclosure in hotlink protection.

    - Core / add-item modules - Fixed Cross Site Scripting
      (XSS) vulnerabilities through malicious file names.

    - Installation (Gallery application) - Update
      web-accessibility protection of the storage folder for
      Apache 2.2.

    - Core (Gallery application) / MIME module - Fixed
      vulnerability in checks for disallowed file extensions
      in file uploads.

    - Gallery Remote module - Added missing permissions
      checks for some GR commands.

    - WebDAV module - Fixed Cross Site Scripting (XSS)
      vulnerability through HTTP PROPPATCH.

    - WebDAV module - Fixed information (item data)
      disclosure in a WebDAV view.

    - WebDAV module - Bug fix for directory listing issue
      (not security related).

    - Comment module - Fixed information (item data)
      disclosure in comment views.

    - Core module (Gallery application) - Improved
      resilience against item information disclosure
      attacks.

    - Slideshow module - Fixed information (item data)
      disclosure in the slideshow.

    - Print modules - Fixed information (item data)
      disclosure in several print modules.

    - Core / print modules - Fixed arbitrary URL redirection
      (phishing attacks) in the core module and several
      print modules.

    - WebCam module - Fixed proxied request weakness.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-December/006234.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c9f27de7"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gallery2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gallery2-ajaxian");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gallery2-albumselect");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gallery2-archiveupload");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gallery2-captcha");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gallery2-carbon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gallery2-cart");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gallery2-classic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gallery2-colorpack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gallery2-comment");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gallery2-customfield");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gallery2-dcraw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gallery2-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gallery2-digibug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gallery2-dynamicalbum");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gallery2-ecard");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gallery2-exif");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gallery2-ffmpeg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gallery2-flashvideo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gallery2-floatrix");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gallery2-fotokasten");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gallery2-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gallery2-getid3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gallery2-hidden");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gallery2-httpauth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gallery2-hybrid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gallery2-icons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gallery2-imageblock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gallery2-imageframe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gallery2-imagemagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gallery2-itemadd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gallery2-keyalbum");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gallery2-linkitem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gallery2-matrix");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gallery2-members");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gallery2-migrate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gallery2-mime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gallery2-mp3audio");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gallery2-multilang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gallery2-multiroot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gallery2-netpbm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gallery2-newitems");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gallery2-nokiaupload");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gallery2-panorama");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gallery2-password");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gallery2-permalinks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gallery2-photoaccess");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gallery2-picasa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gallery2-publishxp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gallery2-quotas");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gallery2-randomhighlight");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gallery2-rating");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gallery2-rearrange");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gallery2-register");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gallery2-remote");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gallery2-replica");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gallery2-reupload");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gallery2-rewrite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gallery2-rss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gallery2-search");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gallery2-shutterfly");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gallery2-siriux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gallery2-sitemap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gallery2-sizelimit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gallery2-slider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gallery2-slideshow");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gallery2-slideshowapplet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gallery2-squarethumb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gallery2-thumbnail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gallery2-thumbpage");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gallery2-tile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gallery2-uploadapplet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gallery2-useralbum");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gallery2-watermark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gallery2-webcam");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gallery2-webdav");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gallery2-zipcart");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:8");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/12/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/12/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");
  script_family(english:"Fedora Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Fedora" >!< release) audit(AUDIT_OS_NOT, "Fedora");
os_ver = eregmatch(pattern: "Fedora.*release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Fedora");
os_ver = os_ver[1];
if (! ereg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 8.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC8", reference:"gallery2-2.2.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"gallery2-ajaxian-2.2.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"gallery2-albumselect-2.2.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"gallery2-archiveupload-2.2.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"gallery2-captcha-2.2.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"gallery2-carbon-2.2.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"gallery2-cart-2.2.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"gallery2-classic-2.2.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"gallery2-colorpack-2.2.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"gallery2-comment-2.2.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"gallery2-customfield-2.2.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"gallery2-dcraw-2.2.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"gallery2-debug-2.2.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"gallery2-digibug-2.2.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"gallery2-dynamicalbum-2.2.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"gallery2-ecard-2.2.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"gallery2-exif-2.2.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"gallery2-ffmpeg-2.2.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"gallery2-flashvideo-2.2.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"gallery2-floatrix-2.2.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"gallery2-fotokasten-2.2.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"gallery2-gd-2.2.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"gallery2-getid3-2.2.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"gallery2-hidden-2.2.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"gallery2-httpauth-2.2.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"gallery2-hybrid-2.2.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"gallery2-icons-2.2.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"gallery2-imageblock-2.2.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"gallery2-imageframe-2.2.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"gallery2-imagemagick-2.2.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"gallery2-itemadd-2.2.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"gallery2-keyalbum-2.2.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"gallery2-linkitem-2.2.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"gallery2-matrix-2.2.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"gallery2-members-2.2.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"gallery2-migrate-2.2.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"gallery2-mime-2.2.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"gallery2-mp3audio-2.2.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"gallery2-multilang-2.2.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"gallery2-multiroot-2.2.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"gallery2-netpbm-2.2.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"gallery2-newitems-2.2.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"gallery2-nokiaupload-2.2.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"gallery2-panorama-2.2.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"gallery2-password-2.2.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"gallery2-permalinks-2.2.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"gallery2-photoaccess-2.2.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"gallery2-picasa-2.2.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"gallery2-publishxp-2.2.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"gallery2-quotas-2.2.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"gallery2-randomhighlight-2.2.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"gallery2-rating-2.2.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"gallery2-rearrange-2.2.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"gallery2-register-2.2.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"gallery2-remote-2.2.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"gallery2-replica-2.2.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"gallery2-reupload-2.2.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"gallery2-rewrite-2.2.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"gallery2-rss-2.2.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"gallery2-search-2.2.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"gallery2-shutterfly-2.2.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"gallery2-siriux-2.2.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"gallery2-sitemap-2.2.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"gallery2-sizelimit-2.2.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"gallery2-slider-2.2.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"gallery2-slideshow-2.2.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"gallery2-slideshowapplet-2.2.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"gallery2-squarethumb-2.2.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"gallery2-thumbnail-2.2.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"gallery2-thumbpage-2.2.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"gallery2-tile-2.2.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"gallery2-uploadapplet-2.2.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"gallery2-useralbum-2.2.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"gallery2-watermark-2.2.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"gallery2-webcam-2.2.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"gallery2-webdav-2.2.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"gallery2-zipcart-2.2.4-1.fc8")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gallery2 / gallery2-ajaxian / gallery2-albumselect / etc");
}
