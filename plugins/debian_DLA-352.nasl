#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-352-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87073);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2015/12/02 20:16:12 $");

  script_name(english:"Debian DLA-352-1 : libcommons-collections3-java security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The Apache commons collection suffered from security issues, making
applications to accept serialized objects from untrusted sources.
Remote attackers might take advantage of these issues to execute
arbitrary Java functions and even inject manipulated bytecode.

This release of libcommons-collection3-java prevents these issues by
disabling the deserialization of the functors classes, unless the
system property
org.apache.commons.collections.enableUnsafeSerialization is set to
'true'. Classes considered unsafe are: CloneTransformer, ForClosure,
InstantiateFactory, InstantiateTransformer, InvokerTransformer,
PrototypeCloneFactory, PrototypeSerializationFactory and WhileClosure.

For Debian 6 'Squeeze', these problems have been fixed in
libcommons-collections3-java version 3.2.1-4+deb6u1. We recommend you
to upgrade your libcommons-collections3-java packages.

Learn more about the Debian Long Term Support (LTS) Project and how to
apply these updates at: https://wiki.debian.org/LTS/

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2015/11/msg00012.html"
  );
  # https://packages.debian.org/source/squeeze-lts/libcommons-collections3-java
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?547eb83a"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://wiki.debian.org/LTS/"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcommons-collections3-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcommons-collections3-java-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
  script_family(english:"Debian Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}


include("audit.inc");
include("debian_package.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/release")) audit(AUDIT_OS_NOT, "Debian");
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (deb_check(release:"6.0", prefix:"libcommons-collections3-java", reference:"3.2.1-4+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"libcommons-collections3-java-doc", reference:"3.2.1-4+deb6u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
