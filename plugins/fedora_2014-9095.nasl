#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2014-9095.
#

include("compat.inc");

if (description)
{
  script_id(77071);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/10/19 22:40:33 $");

  script_xref(name:"FEDORA", value:"2014-9095");

  script_name(english:"Fedora 20 : v8-3.14.5.10-11.fc20 (2014-9095)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"TJ Fontaine of the Node.js project reports :

A memory corruption vulnerability, which results in a
denial-of-service, was identified in the versions of V8 that ship with
Node.js 0.8 and 0.10. In certain circumstances, a particularly deep
recursive workload that may trigger a GC and receive an interrupt may
overflow the stack and result in a segmentation fault. For instance,
if your work load involves successive `JSON.parse` calls and the
parsed objects are significantly deep, you may experience the process
aborting while parsing.

This issue was identified by Tom Steele of [^Lift
Security](https://liftsecurity.io/) and Fedor Indunty, Node.js Core
Team member worked closely with the V8 team to find our resolution.

The V8 issue is described here
https://codereview.chromium.org/339883002

It has landed in the Node repository here:
https://github.com/joyent/node/commit/530af9cb8e700e7596b3ec812bad123c
9fa06356

And has been released in the following versions :

  - [v0.10.30](http://nodejs.org/dist/v0.10.30)
    http://blog.nodejs.org/2014/07/31/node-v0-10-30-stable/

  - [v0.8.28](http://nodejs.org/dist/v0.8.28)
    http://blog.nodejs.org/2014/07/31/node-v0-8-28-maintenan
    ce/

### The Fix

[Applied in this update.]

### Remediation

The best course of action is to patch or upgrade Node.js.

### Mitigation

To mitigate against deep JSON parsing you can limit the size of the
string you parse against, or ban clients who trigger a `RangeError`
for parsing JSON.

There is no specific maximum size of a JSON string, though keeping the
max to the size of your known message bodies is suggested. If your
message bodies cannot be over 20K, there's no reason to accept 1MB
bodies.

For web frameworks that do automatic JSON parsing, you may need to
configure the routes that accept JSON payloads to have a maximum body
size.

  - [expressjs](http://expressjs.com) and
    [krakenjs](http://krakenjs.com) used with the
    [body-parser](https://github.com/expressjs/body-parser#b
    odyparserjsonoptions) plugin accepts a `limit` parameter
    in your JSON config

  - [Hapi.js](http://hapijs.com) has `payload.maxBytes`
    https://github.com/spumko/hapi/blob/master/docs/Referenc
    e.md

  -
    [restify](http://mcavage.me/node-restify/#Bundled-Plugin
    s) bundled `bodyParser` accepts a `maxBodySize`

Source:
https://groups.google.com/d/msg/nodejs/-siJEObdp10/2xcqqmTHiEMJ

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://blog.nodejs.org/2014/07/31/node-v0-10-30-stable/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://blog.nodejs.org/2014/07/31/node-v0-8-28-maintenance/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://expressjs.com"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://hapijs.com"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://krakenjs.com"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://mcavage.me/node-restify/#Bundled-Plugins"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://nodejs.org/dist/v0.10.30"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://nodejs.org/dist/v0.8.28"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1125464"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://codereview.chromium.org/339883002"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/expressjs/body-parser#bodyparserjsonoptions"
  );
  # https://github.com/joyent/node/commit/530af9cb8e700e7596b3ec812bad123c9fa06356
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a86e6922"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/spumko/hapi/blob/master/docs/Reference.md"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://groups.google.com/d/msg/nodejs/-siJEObdp10/2xcqqmTHiEMJ"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://liftsecurity.io/"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-August/136333.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1a0e85fa"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected v8 package.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:v8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:20");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^20([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 20.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC20", reference:"v8-3.14.5.10-11.fc20")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "v8");
}
