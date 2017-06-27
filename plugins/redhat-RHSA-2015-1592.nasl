#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:1592. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85716);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2017/01/06 16:01:52 $");

  script_cve_id("CVE-2013-4346", "CVE-2013-4347", "CVE-2014-3653", "CVE-2015-1816", "CVE-2015-1844", "CVE-2015-3155", "CVE-2015-3235");
  script_osvdb_id(97244, 97245, 111911, 119912, 120135, 121427, 123391);
  script_xref(name:"RHSA", value:"2015:1592");

  script_name(english:"RHEL 6 : Satellite Server (RHSA-2015:1592)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Red Hat Satellite 6.1 now available for Red Hat Enterprise Linux 6.

Red Hat Product Security has rated this update as having an important
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

Red Hat Satellite is a system management solution that allows
organizations to configure and maintain their systems without the
necessity to provide public Internet access to their servers or other
client systems. It performs provisioning and configuration management
of predefined standard operating environments.

This update provides Satellite 6.1 packages for Red Hat Enterprise
Linux 6. For the full list of new features provided by Satellite 6.1
see the Release notes linked to in References section. (BZ#1201357)

It was discovered that, in Foreman, the edit_users permission (for
example, granted to the Manager role) allowed the user to edit admin
user passwords. An attacker with the edit_users permission could use
this flaw to access an admin user account, leading to an escalation of
privileges. (CVE-2015-3235)

It was found that Foreman did not set the HttpOnly flag on session
cookies. This could allow a malicious script to access the session
cookie. (CVE-2015-3155)

It was found that when making an SSL connection to an LDAP
authentication source in Foreman, the remote server certificate was
accepted without any verification against known certificate
authorities, potentially making TLS connections vulnerable to
man-in-the-middle attacks. (CVE-2015-1816)

A flaw was found in the way Foreman authorized user actions on
resources via the API when an organization was not explicitly set. A
remote attacker could use this flaw to obtain additional information
about resources they were not authorized to access. (CVE-2015-1844)

A cross-site scripting (XSS) flaw was found in Foreman's template
preview screen. A remote attacker could use this flaw to perform
cross-site scripting attacks by tricking a user into viewing a
malicious template. Note that templates are commonly shared among
users. (CVE-2014-3653)

It was found that python-oauth2 did not properly verify the nonce of a
signed URL. An attacker able to capture network traffic of a website
using OAuth2 authentication could use this flaw to conduct replay
attacks against that website. (CVE-2013-4346)

It was found that python-oauth2 did not properly generate random
values for use in nonces. An attacker able to capture network traffic
of a website using OAuth2 authentication could use this flaw to
conduct replay attacks against that website. (CVE-2013-4347)

Red Hat would like to thank Rufus Jarnefelt of Coresec for reporting
the Foreman HttpOnly issue.

All users who require Satellite 6.1 are advised to install these new
packages."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2015-1592.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-4346.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-4347.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-3653.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-1816.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-1844.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-3155.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-3235.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:aopalliance");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:apache-commons-codec-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:apache-mime4j");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atinject");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bcmail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bcpg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bcprov");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bctsp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bouncycastle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:c3p0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:candlepin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:candlepin-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:candlepin-scl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:candlepin-scl-quartz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:candlepin-scl-rhino");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:candlepin-scl-runtime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:candlepin-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:candlepin-tomcat6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:createrepo_c");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:createrepo_c-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:createrepo_c-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:dom4j");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:elasticsearch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:facter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:facter-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fasterxml-oss-parent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-compute");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-discovery-image");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-gce");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-ovirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-vmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gettext-commons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glassfish-jaf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glassfish-javamail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gofer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:google-collections");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:google-guice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gperftools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gperftools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gutterball");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate-beanvalidation-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate-jpa-2.0-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate3-commons-annotations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate4-c3p0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate4-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate4-entitymanager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate4-validator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hiera");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hornetq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpcomponents-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpcomponents-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpcomponents-project");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpcore");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ipxe-bootimgs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:istack-commons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:istack-commons-runtime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jackson-annotations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jackson-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jackson-databind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jackson-datatype-hibernate-parent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jackson-datatype-hibernate4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jackson-jaxrs-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jackson-jaxrs-json-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jackson-jaxrs-providers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jackson-module-jaxb-annotations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:javassist");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jaxb-impl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jaxb-project");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-common-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-jaxb-api_2.2_spec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-logging");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-specs-parent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-transaction-api_1.1_spec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jcl-over-slf4j");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jsr311-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:katello");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:katello-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:katello-certs-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:katello-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:katello-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:katello-installer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:katello-installer-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:katello-service");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:katello-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libmongodb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libqpid-dispatch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:liquibase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:livecd-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:logback-classic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:logback-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:logback-parent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:lucene4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:lucene4-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_passenger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_wsgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_wsgi-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mongodb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mongodb-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mongodb-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:netty");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:oauth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:objectweb-asm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openscap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openscap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openscap-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openscap-scanner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openscap-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pulp-admin-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pulp-docker-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pulp-katello");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pulp-nodes-child");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pulp-nodes-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pulp-nodes-parent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pulp-puppet-admin-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pulp-puppet-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pulp-puppet-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pulp-rpm-admin-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pulp-rpm-handlers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pulp-rpm-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pulp-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pulp-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:puppet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:puppet-foreman_scap_client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:puppet-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:puppetlabs-stdlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pyliblzma");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pyliblzma-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pyparsing");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-BeautifulSoup");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-amqp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-anyjson");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-billiard");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-billiard-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-blinker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-bson");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-celery");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-cherrypy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-crane");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-flask");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-gofer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-gofer-proton");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-gofer-qpid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-httplib2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-imgcreate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-importlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-isodate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-itsdangerous");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-jinja2-26");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-kombu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-mongoengine");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-nectar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-oauth2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-okaara");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pulp-agent-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pulp-bindings");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pulp-client-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pulp-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pulp-docker-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pulp-puppet-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pulp-rpm-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pymongo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pymongo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pymongo-gridfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-qpid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-qpid-proton");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-qpid-qmf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-requests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-saslwrapper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-semantic-version");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-webpy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-werkzeug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-cpp-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-cpp-client-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-cpp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-cpp-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-cpp-server-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-cpp-server-linearstore");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-dispatch-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-dispatch-router");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-dispatch-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-java-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-java-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-proton-c");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-proton-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-qmf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-qmf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:resteasy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby-augeas");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby-augeas-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby-rgen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby-shadow");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby-shadow-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-facter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-ruby-wrapper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-addressable");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-algebrick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-ancestry");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-anemone");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-angular-rails-templates");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-ansi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-apipie-params");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-apipie-rails");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-archive-tar-minitar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-audited");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-audited-activerecord");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-autoparse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-bastion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-bundler_ext");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-commonjs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-daemons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-deep_cloneable");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-deface");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-docker-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-dynflow");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-excon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-extlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-faraday");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-fast_gettext");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-ffi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-ffi-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-fog");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-fog-brightbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-fog-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-fog-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-fog-radosgw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-fog-sakuracloud");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-fog-softlayer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-fog-xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-foreigner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-foreman-redhat_access");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-foreman-tasks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-foreman_abrt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-foreman_bootdisk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-foreman_discovery");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-foreman_docker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-foreman_gutterball");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-foreman_hooks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-foreman_openscap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-formatador");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-friendly_id");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-gettext_i18n_rails");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-gettext_i18n_rails_js");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-google-api-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-haml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-haml-rails");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-hashr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-hooks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-hpricot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-hpricot-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-i18n_data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-ipaddress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-jquery-ui-rails");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-justified");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-jwt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-katello");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-launchy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-ldap_fluff");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-less");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-less-rails");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-little-plugger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-logging");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-multi_json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-multi_json-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-multipart-post");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-net-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-net-scp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-net-ssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-nokogiri");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-nokogiri-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-oauth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-openscap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-ovirt_provision_plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-passenger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-passenger-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-passenger-native");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-passenger-native-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-pg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-pg-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-po_to_json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-qpid_messaging");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-qpid_messaging-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-rabl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-rbovirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-rbvmomi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-redhat_access_lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-rest-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-robotex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-ruby-libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-ruby-libvirt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-ruby2ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-ruby_parser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-runcible");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-safemode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-sass");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-sass-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-scaptimony");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-scoped_search");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-secure_headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-sequel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-sexp_processor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-signet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-sprockets");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-sprockets-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-sshkey");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-strong_parameters");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-tire");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-trollop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-unf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-unf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-unf_ext");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-unf_ext-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-uuidtools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-validates_lengths_from_database");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-wicked");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-will_paginate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-ansi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-apipie-bindings");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-awesome_print");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-bundler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-bundler_ext");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-clamp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-fast_gettext");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-fastercsv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-ffi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-ffi-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-foreman_scap_client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-gssapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-hammer_cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-hammer_cli_csv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-hammer_cli_foreman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-hammer_cli_foreman_bootdisk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-hammer_cli_foreman_discovery");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-hammer_cli_foreman_docker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-hammer_cli_foreman_docker-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-hammer_cli_foreman_tasks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-hammer_cli_gutterball");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-hammer_cli_import");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-hammer_cli_katello");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-hashie");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-highline");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-json-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-kafo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-kafo_parsers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-little-plugger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-locale");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-logging");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-mime-types");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-multi_json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-multi_json-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-oauth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-passenger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-passenger-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-passenger-native");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-passenger-native-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-powerbar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-rack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-rack-protection");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-rake");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-rb-readline");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-rdoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-rdoc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-rest-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-rkerberos");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-rkerberos-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-rubyipmi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-satyr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-sinatra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-smart_proxy_abrt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-smart_proxy_discovery");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-smart_proxy_openscap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-smart_proxy_pulp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-table_print");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-thor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-tilt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:saslwrapper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:saslwrapper-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:scannotation");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sigar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sigar-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sigar-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sisu-cglib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:slf4j-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:slf4j-parent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:snappy-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:snappy-java-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sun-txw2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:v8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:v8-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = eregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2015:1592";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : yum_report 
    );
    exit(0);
  }
  else
  {
    audit_message = "affected by Red Hat security advisory " + rhsa;
    audit(AUDIT_OS_NOT, audit_message);
  }
}
else
{
  flag = 0;

  if (! (rpm_exists(release:"RHEL6", rpm:"spacewalk-admin-"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "Satellite Server");

  if (rpm_check(release:"RHEL6", reference:"aopalliance-1.0-5.3.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"apache-commons-codec-eap6-1.4-16.redhat_3.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"apache-mime4j-0.6-4_redhat_1.ep6.el6.1")) flag++;
  if (rpm_check(release:"RHEL6", reference:"atinject-1-8.2_redhat_1.ep6.el6.1")) flag++;
  if (rpm_check(release:"RHEL6", reference:"bcmail-1.46-3.5_redhat_1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"bcpg-1.46-3.5_redhat_1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"bcprov-1.46-3.5_redhat_1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"bctsp-1.46-3.5_redhat_1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"bouncycastle-1.46-3.5_redhat_1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"c3p0-0.9.1.2-2.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"candlepin-0.9.49.3-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"candlepin-common-1.0.22-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"candlepin-scl-1-5.el6_4")) flag++;
  if (rpm_check(release:"RHEL6", reference:"candlepin-scl-quartz-2.1.5-5.el6_4")) flag++;
  if (rpm_check(release:"RHEL6", reference:"candlepin-scl-rhino-1.7R3-1.el6_4")) flag++;
  if (rpm_check(release:"RHEL6", reference:"candlepin-scl-runtime-1-5.el6_4")) flag++;
  if (rpm_check(release:"RHEL6", reference:"candlepin-selinux-0.9.49.3-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"candlepin-tomcat6-0.9.49.3-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"createrepo_c-0.7.4-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"createrepo_c-debuginfo-0.7.4-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"createrepo_c-libs-0.7.4-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"dom4j-1.6.1-11.8_redhat_1.ep6.el6.1")) flag++;
  if (rpm_check(release:"RHEL6", reference:"elasticsearch-0.90.10-7.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"facter-1.7.6-2.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"facter-debuginfo-1.7.6-2.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"fasterxml-oss-parent-11-2.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"foreman-1.7.2.33-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"foreman-compute-1.7.2.33-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"foreman-debug-1.7.2.33-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"foreman-discovery-image-2.1.0-36.el7sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"foreman-gce-1.7.2.33-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"foreman-libvirt-1.7.2.33-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"foreman-ovirt-1.7.2.33-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"foreman-postgresql-1.7.2.33-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"foreman-proxy-1.7.2.5-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"foreman-selinux-1.7.2.13-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"foreman-vmware-1.7.2.33-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"gettext-commons-0.9.6-6.el6_2")) flag++;
  if (rpm_check(release:"RHEL6", reference:"glassfish-jaf-1.1.1-9_redhat_1.ep6.el6.1")) flag++;
  if (rpm_check(release:"RHEL6", reference:"glassfish-javamail-1.4.4-6_redhat_1.ep6.el6.1")) flag++;
  if (rpm_check(release:"RHEL6", reference:"gofer-2.6.2-2.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"google-collections-1.0-3.3.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"google-guice-3.0-2_redhat_1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"gperftools-debuginfo-2.0-3.el6sat.2")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"gperftools-libs-2.0-3.el6sat.2")) flag++;
  if (rpm_check(release:"RHEL6", reference:"gutterball-1.0.15.0-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"hibernate-beanvalidation-api-1.0.0-4.7.GA_redhat_2.ep6.el6.3")) flag++;
  if (rpm_check(release:"RHEL6", reference:"hibernate-jpa-2.0-api-1.0.1-5.Final_redhat_2.1.ep6.el6.4")) flag++;
  if (rpm_check(release:"RHEL6", reference:"hibernate3-commons-annotations-4.0.1-2.Final_redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"hibernate4-c3p0-4.2.5-1.Final_redhat_1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"hibernate4-core-4.2.5-1.Final_redhat_1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"hibernate4-entitymanager-4.2.5-1.Final_redhat_1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"hibernate4-validator-4.3.1-2.Final_redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"hiera-1.0.0-3.el6_4")) flag++;
  if (rpm_check(release:"RHEL6", reference:"hornetq-2.3.5-2.Final_redhat_2.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"httpclient-4.2.1-9.redhat_1.3.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"httpcomponents-client-4.2.1-9.redhat_1.3.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"httpcomponents-core-4.2.1-9.redhat_1.3.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"httpcomponents-project-6-9.redhat_1.3.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"httpcore-4.2.1-9.redhat_1.3.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ipxe-bootimgs-20130517-7.1fm.gitc4bce43.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"istack-commons-2.6.1-9_redhat_2.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"istack-commons-runtime-2.6.1-9_redhat_2.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jackson-annotations-2.3.0-3.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jackson-core-2.3.0-1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jackson-databind-2.3.0-2.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jackson-datatype-hibernate-parent-2.3.0-1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jackson-datatype-hibernate4-2.3.0-1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jackson-jaxrs-base-2.3.0-3.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jackson-jaxrs-json-provider-2.3.0-3.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jackson-jaxrs-providers-2.3.0-3.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jackson-module-jaxb-annotations-2.3.0-2.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"javassist-3.12.1-1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jaxb-impl-2.2.5-19.redhat_7.2.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jaxb-project-2.2.5-19.redhat_7.2.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-common-core-2.2.17-4.GA_redhat_1.ep6.el6.1")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-jaxb-api_2.2_spec-1.0.4-3.Final_redhat_2.1.ep6.el6.1")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-logging-3.1.2-3.GA_redhat_1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-specs-parent-1.0.0-1.Beta2_redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-transaction-api_1.1_spec-1.0.1-6.Final_redhat_2.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jbossts-4.16.2-1.Final.3.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jcl-over-slf4j-1.7.5-4.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jsr311-api-1.1.1-4.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"katello-2.2.0.14-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"katello-agent-2.2.5-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"katello-certs-tools-2.2.1-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"katello-common-2.2.0.14-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"katello-debug-2.2.0.14-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"katello-installer-2.3.17-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"katello-installer-base-2.3.17-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"katello-service-2.2.0.14-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"katello-utils-2.2.5-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libmongodb-2.4.6-2.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libqpid-dispatch-0.4-7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"liquibase-3.1.0-5.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"livecd-tools-13.4.1-2.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"logback-classic-1.0.13-3.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"logback-core-1.0.13-3.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"logback-parent-1.0.13-3.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"lucene4-4.6.1-1.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"lucene4-contrib-4.6.1-1.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"mod_passenger-4.0.18-19.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"mod_wsgi-3.4-1.pulp.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"mod_wsgi-debuginfo-3.4-1.pulp.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"mongodb-2.4.6-2.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"mongodb-debuginfo-2.4.6-2.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"mongodb-server-2.4.6-2.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"netty-3.2.6-1_redhat_1.2.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"oauth-20100601-4.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"objectweb-asm-3.3.1-5_redhat_1.1.ep6.el6.1")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openscap-1.2.4-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openscap-debuginfo-1.2.4-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openscap-python-1.2.4-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openscap-scanner-1.2.4-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openscap-utils-1.2.4-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"pulp-admin-client-2.6.0.15-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"pulp-docker-plugins-0.2.5-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"pulp-katello-0.5-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"pulp-nodes-child-2.6.0.15-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"pulp-nodes-common-2.6.0.15-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"pulp-nodes-parent-2.6.0.15-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"pulp-puppet-admin-extensions-2.6.0.15-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"pulp-puppet-plugins-2.6.0.15-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"pulp-puppet-tools-2.6.0.15-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"pulp-rpm-admin-extensions-2.6.0.15-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"pulp-rpm-handlers-2.6.0.15-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"pulp-rpm-plugins-2.6.0.15-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"pulp-selinux-2.6.0.15-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"pulp-server-2.6.0.15-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"puppet-3.6.2-4.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"puppet-foreman_scap_client-0.3.3-9.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"puppet-server-3.6.2-4.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"puppetlabs-stdlib-4.2.1-1.20140510git08b00d9.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"pyliblzma-0.5.3-3.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"pyliblzma-debuginfo-0.5.3-3.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"pyparsing-1.5.6-6.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"python-BeautifulSoup-3.0.8.1-1.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"python-amqp-1.4.6-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"python-anyjson-0.3.3-4.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"python-billiard-3.3.0.17-1.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"python-billiard-debuginfo-3.3.0.17-1.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"python-blinker-1.3-2.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"python-bson-2.5.2-3.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"python-celery-3.1.11-1.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"python-cherrypy-3.2.2-3.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"python-crane-0.2.2-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"python-flask-0.10.1-4.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"python-gofer-2.6.2-2.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"python-gofer-proton-2.6.2-2.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"python-gofer-qpid-2.6.2-2.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"python-httplib2-0.7.2-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"python-imgcreate-13.4.1-2.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"python-importlib-1.0.2-1.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"python-isodate-0.5.0-4.pulp.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"python-itsdangerous-0.23-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"python-jinja2-26-2.6-3.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"python-kombu-3.0.24-10.pulp.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"python-mongoengine-0.7.10-2.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"python-nectar-1.3.1-2.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"python-oauth2-1.5.211-8.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"python-okaara-1.0.32-1.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"python-pulp-agent-lib-2.6.0.15-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"python-pulp-bindings-2.6.0.15-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"python-pulp-client-lib-2.6.0.15-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"python-pulp-common-2.6.0.15-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"python-pulp-docker-common-0.2.5-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"python-pulp-puppet-common-2.6.0.15-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"python-pulp-rpm-common-2.6.0.15-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"python-pymongo-2.5.2-3.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"python-pymongo-debuginfo-2.5.2-3.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"python-pymongo-gridfs-2.5.2-3.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"python-qpid-0.30-6.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"python-qpid-proton-0.9-4.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"python-qpid-qmf-0.30-5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"python-requests-2.4.3-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"python-saslwrapper-0.22-5.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"python-semantic-version-2.2.0-3.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"python-webpy-0.37-3.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"python-werkzeug-0.8.3-2.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"qpid-cpp-client-0.30-9.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"qpid-cpp-client-devel-0.30-9.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"qpid-cpp-debuginfo-0.30-9.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"qpid-cpp-server-0.30-9.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"qpid-cpp-server-devel-0.30-9.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"qpid-cpp-server-linearstore-0.30-9.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"qpid-dispatch-debuginfo-0.4-7.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"qpid-dispatch-router-0.4-7.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"qpid-dispatch-tools-0.4-7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"qpid-java-client-0.30-3.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"qpid-java-common-0.30-3.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"qpid-proton-c-0.9-4.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"qpid-proton-debuginfo-0.9-4.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"qpid-qmf-0.30-5.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"qpid-qmf-debuginfo-0.30-5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"qpid-tools-0.30-4.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"resteasy-2.3.7.2-1.Final_redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ruby-augeas-0.4.1-1.el6_4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ruby-augeas-debuginfo-0.4.1-1.el6_4")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby-rgen-0.6.5-2.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ruby-shadow-1.4.1-13.el6_4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ruby-shadow-debuginfo-1.4.1-13.el6_4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ruby193-facter-1.6.18-5.el6_4")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-ruby-wrapper-0.0.2-6.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-addressable-2.3.5-2.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-algebrick-0.4.0-3.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-ancestry-2.0.0-1.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-anemone-0.7.2-11.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-angular-rails-templates-0.1.2-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-ansi-1.4.3-3.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-apipie-params-0.0.3-2.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-apipie-rails-0.2.5-1.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-archive-tar-minitar-0.5.2-9.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-audited-3.0.0-5.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-audited-activerecord-3.0.0-8.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-autoparse-0.3.3-2.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-bastion-0.3.0.10-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-bundler_ext-0.3.0-6.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-commonjs-0.2.7-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-daemons-1.1.4-10.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-deep_cloneable-2.0.0-4.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-deface-0.7.2-7.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-docker-api-1.17.0-1.1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-dynflow-0.7.7.9-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-excon-0.38.0-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-extlib-0.9.16-2.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-faraday-0.8.8-2.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-fast_gettext-0.8.0-13.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ruby193-rubygem-ffi-1.0.9-11.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ruby193-rubygem-ffi-debuginfo-1.0.9-11.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-fog-1.24.0-3.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-fog-brightbox-0.0.1-2.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-fog-core-1.24.0-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-fog-json-1.0.0-2.1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-fog-radosgw-0.0.3-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-fog-sakuracloud-0.1.1-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-fog-softlayer-0.3.9-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-fog-xml-0.1.0-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-foreigner-1.4.2-1.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-foreman-redhat_access-0.2.1-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-foreman-tasks-0.6.15.4-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-foreman_abrt-0.0.5-2.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-foreman_bootdisk-4.0.2.13-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-foreman_discovery-2.0.0.19-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-foreman_docker-1.2.0.18-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-foreman_gutterball-0.0.1.9-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-foreman_hooks-0.3.7-2.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-foreman_openscap-0.3.2.10-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-formatador-0.2.1-9.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-friendly_id-4.0.10.1-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-gettext_i18n_rails-0.10.0-3.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-gettext_i18n_rails_js-0.0.8-3.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-google-api-client-0.6.4-2.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-haml-3.1.6-6.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-haml-rails-0.3.4-8.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-hashr-0.0.22-5.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-hooks-0.2.2-7.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ruby193-rubygem-hpricot-0.8.6-11.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ruby193-rubygem-hpricot-debuginfo-0.8.6-11.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-i18n_data-0.2.7-5.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-ipaddress-0.8.0-6.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-jquery-ui-rails-4.0.2-8.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-justified-0.0.4-4.el6sam")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-jwt-0.1.8-2.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-katello-2.2.0.65-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-launchy-2.3.0-2.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-ldap_fluff-0.3.2-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-less-2.5.1-2.1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-less-rails-2.5.0-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-little-plugger-1.1.3-17.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-logging-1.8.1-26.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-multi_json-1.8.2-4.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-multi_json-doc-1.8.2-4.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-multipart-post-1.2.0-3.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-net-ldap-0.3.1-3.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-net-scp-1.1.0-5.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-net-ssh-2.6.7-5.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ruby193-rubygem-nokogiri-1.5.11-1.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ruby193-rubygem-nokogiri-debuginfo-1.5.11-1.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-oauth-0.4.7-8.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-openscap-0.4.2-2.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-ovirt_provision_plugin-1.0.1.2-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ruby193-rubygem-passenger-4.0.18-19.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ruby193-rubygem-passenger-debuginfo-4.0.18-19.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ruby193-rubygem-passenger-native-4.0.18-19.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ruby193-rubygem-passenger-native-libs-4.0.18-19.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ruby193-rubygem-pg-0.12.2-10.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ruby193-rubygem-pg-debuginfo-0.12.2-10.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-po_to_json-0.0.7-3.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ruby193-rubygem-qpid_messaging-0.30.0-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ruby193-rubygem-qpid_messaging-debuginfo-0.30.0-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-rabl-0.9.0-1.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-rbovirt-0.0.29-1.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-rbvmomi-1.6.0-3.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-redhat_access_lib-0.0.4-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-rest-client-1.6.7-1.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-robotex-1.0.0-16.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ruby193-rubygem-ruby-libvirt-0.5.1-1.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ruby193-rubygem-ruby-libvirt-debuginfo-0.5.1-1.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-ruby2ruby-2.0.1-9.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-ruby_parser-3.1.1-15.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-runcible-1.3.5-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-safemode-1.2.1-1.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-sass-3.2.13-1.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-sass-doc-3.2.13-1.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-scaptimony-0.3.0.1-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-scoped_search-2.7.1-2.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-secure_headers-1.3.3-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-sequel-3.45.0-6.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-sexp_processor-4.1.3-7.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-signet-0.4.5-2.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-sprockets-2.10.1-3.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-sprockets-doc-2.10.1-3.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-sshkey-1.6.0-3.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-strong_parameters-0.2.1-11.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-tire-0.6.2-1.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-trollop-2.0-5.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ruby193-rubygem-unf-0.1.3-4.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ruby193-rubygem-unf-debuginfo-0.1.3-4.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ruby193-rubygem-unf_ext-0.0.6-5.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ruby193-rubygem-unf_ext-debuginfo-0.0.6-5.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-uuidtools-2.1.3-6.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-validates_lengths_from_database-0.2.0-1.3.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-wicked-1.1.0-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-will_paginate-3.0.2-10.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-ansi-1.4.3-3.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-apipie-bindings-0.0.11-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-awesome_print-1.0.2-12.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-bundler-1.0.15-5.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-bundler_ext-0.3.0-7.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-clamp-0.6.2-2.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-fast_gettext-0.8.0-13.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-fastercsv-1.5.4-10.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"rubygem-ffi-1.4.0-3.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"rubygem-ffi-debuginfo-1.4.0-3.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-foreman_scap_client-0.1.0.4-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-gssapi-1.1.2-4.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-hammer_cli-0.1.4.11-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-hammer_cli_csv-0.0.6.5-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-hammer_cli_foreman-0.1.4.14-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-hammer_cli_foreman_bootdisk-0.1.2.7-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-hammer_cli_foreman_discovery-0.0.1.10-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-hammer_cli_foreman_docker-0.0.3.9-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-hammer_cli_foreman_docker-doc-0.0.3.9-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-hammer_cli_foreman_tasks-0.0.3.5-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-hammer_cli_gutterball-0.0.1.3-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-hammer_cli_import-0.10.19-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-hammer_cli_katello-0.0.7.17-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-hashie-2.0.5-2.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-highline-1.6.21-1.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"rubygem-json-1.4.6-2.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"rubygem-json-debuginfo-1.4.6-2.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-kafo-0.6.5.9-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-kafo_parsers-0.0.4.4-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-little-plugger-1.1.3-17.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-locale-2.0.9-7.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-logging-1.8.1-26.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-mime-types-1.19-7.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-multi_json-1.8.2-4.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-multi_json-doc-1.8.2-4.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-oauth-0.4.7-8.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"rubygem-passenger-4.0.18-19.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"rubygem-passenger-debuginfo-4.0.18-19.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"rubygem-passenger-native-4.0.18-19.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"rubygem-passenger-native-libs-4.0.18-19.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-powerbar-1.0.11-8.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-rack-1.4.1-13.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-rack-protection-1.5.0-7.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-rake-0.9.2.2-41.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-rb-readline-0.5.1-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"rubygem-rdoc-3.12-27.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"rubygem-rdoc-debuginfo-3.12-27.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-rest-client-1.6.7-1.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"rubygem-rkerberos-0.1.2-3.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"rubygem-rkerberos-debuginfo-0.1.2-3.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-rubyipmi-0.10.0-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-satyr-0.2-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-sinatra-1.3.6-27.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-smart_proxy_abrt-0.0.6-5.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-smart_proxy_discovery-1.0.2.1-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-smart_proxy_openscap-0.3.0.9-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-smart_proxy_pulp-1.0.1.2-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-table_print-1.5.1-3.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-thor-0.14.6-5.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-tilt-1.3.3-18.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"saslwrapper-0.22-5.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"saslwrapper-debuginfo-0.22-5.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"scannotation-1.0.2-4.redhat_1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"sigar-1.6.5-0.9.git58097d9.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"sigar-debuginfo-1.6.5-0.9.git58097d9.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"sigar-java-1.6.5-0.9.git58097d9.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"sisu-cglib-2.2.2-2.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"slf4j-api-1.7.5-4.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"slf4j-parent-1.7.5-4.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"snappy-java-1.0.4-2.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"snappy-java-debuginfo-1.0.4-2.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"sun-txw2-20110809-5_redhat_2.ep6.el6.3")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"v8-3.14.5.10-9.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"v8-debuginfo-3.14.5.10-9.el6sat")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "aopalliance / apache-commons-codec-eap6 / apache-mime4j / atinject / etc");
  }
}
