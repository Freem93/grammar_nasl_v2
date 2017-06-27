#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:0946. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63988);
  script_version("$Revision: 1.22 $");
  script_cvs_date("$Date: 2017/01/05 14:44:34 $");

  script_cve_id("CVE-2011-2196");
  script_bugtraq_id(48716);
  script_osvdb_id(74277);
  script_xref(name:"RHSA", value:"2011:0946");
  script_xref(name:"IAVB", value:"2011-B-0086");

  script_name(english:"RHEL 6 : JBoss EAP (RHSA-2011:0946)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated JBoss Enterprise Application Platform 5.1.1 packages that fix
one security issue and various bugs are now available for Red Hat
Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
important security impact. A Common Vulnerability Scoring System
(CVSS) base score, which gives a detailed severity rating, is
available from the CVE link in the References section.

JBoss Enterprise Application Platform is the market-leading platform
for innovative and scalable Java applications. JBoss Enterprise
Application Platform integrates the JBoss Application Server with
JBoss Hibernate and JBoss Seam into a complete and simple enterprise
solution.

This JBoss Enterprise Application Platform 5.1.1 release for Red Hat
Enterprise Linux 6 serves as a replacement for JBoss Enterprise
Application Platform 5.1.0.

These updated packages include the bug fixes detailed in the release
notes, which are linked to from the References section of this
erratum.

The following security issue is also fixed with this release :

It was found that the fix for CVE-2011-1484 was incomplete: JBoss Seam
2 did not block access to all malicious JBoss Expression Language (EL)
constructs in page exception handling, allowing arbitrary Java methods
to be executed. A remote attacker could use this flaw to execute
arbitrary code via a specially crafted URL provided to certain
applications based on the JBoss Seam 2 framework. Note: A properly
configured and enabled Java Security Manager would prevent
exploitation of this flaw. (CVE-2011-2196)

Red Hat would like to thank the ObjectWorks+ Development Team at
Nomura Research Institute for reporting this issue.

Warning: Before applying this update, please back up your JBoss
Enterprise Application Platform's 'jboss-as/server/[PROFILE]/deploy/'
directory, along with all other customized configuration files.

All users of JBoss Enterprise Application Platform 5.1.0 on Red Hat
Enterprise Linux 6 are advised to upgrade to these updated packages.
Manual action is required for this update to take effect. Refer to the
Solution section for details."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-2196.html"
  );
  # http://docs.redhat.com/docs/en-US/JBoss_Enterprise_Application_Platform/5/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f390cc27"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2011-0946.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:antlr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:apache-cxf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:apache-james");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:avalon-framework");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:avalon-logkit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bcel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bsf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bsh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bsh2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bsh2-bsf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cglib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:codehaus-jackson");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:codehaus-jackson-core-asl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:codehaus-jackson-jaxrs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:codehaus-jackson-mapper-asl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:codehaus-stax");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:codehaus-stax-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:concurrent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:dom4j");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:dtdparser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ecj3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:facelets");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glassfish-jaf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glassfish-javamail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glassfish-jaxb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glassfish-jaxws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glassfish-jsf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glassfish-jstl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gnu-getopt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gnu-trove");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate3-annotations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate3-annotations-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate3-commons-annotations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate3-commons-annotations-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate3-ejb-persistence-3.0-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate3-ejb-persistence-3.0-api-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate3-entitymanager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate3-entitymanager-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate3-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate3-search");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate3-search-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate3-validator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate3-validator-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hornetq-jopr-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hsqldb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:i18nlog");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:isorelax");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jacorb-jboss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jakarta-commons-beanutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jakarta-commons-codec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jakarta-commons-collections");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jakarta-commons-collections-tomcat5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jakarta-commons-dbcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jakarta-commons-dbcp-tomcat5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jakarta-commons-digester");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jakarta-commons-discovery");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jakarta-commons-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jakarta-commons-httpclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jakarta-commons-io");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jakarta-commons-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jakarta-commons-logging");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jakarta-commons-logging-jboss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jakarta-commons-parent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jakarta-commons-pool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jakarta-commons-pool-tomcat5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jakarta-oro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:javassist");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jaxbintros");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jaxen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-aop2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-aspects-build");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-aspects-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-bootstrap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-cache-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-cache-pojo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-cl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-cluster-ha-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-cluster-ha-server-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-cluster-ha-server-cache-jbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-cluster-ha-server-cache-spi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-common-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-common-logging-jdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-common-logging-log4j");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-common-logging-spi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-current-invocation-aspects");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-deployers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-eap5-native");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-ejb-3.0-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-ejb3-build");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-ejb3-cache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-ejb3-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-ejb3-context");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-ejb3-context-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-ejb3-context-naming");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-ejb3-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-ejb3-deployers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-ejb3-endpoint");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-ejb3-endpoint-deployer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-ejb3-ext-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-ejb3-ext-api-impl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-ejb3-interceptors");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-ejb3-jpa-int");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-ejb3-mc-int");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-ejb3-metadata");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-ejb3-metrics-deployer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-ejb3-proxy-clustered");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-ejb3-proxy-impl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-ejb3-proxy-spi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-ejb3-security");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-ejb3-timeout");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-ejb3-timeout-3.0-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-ejb3-timeout-spi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-ejb3-timerservice-spi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-ejb3-transactions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-ejb3-vfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-ejb3-vfs-impl-vfs2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-ejb3-vfs-spi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-integration");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-jacc-1.1-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-jad-1.2-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-jaspi-1.0-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-javaee");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-javaee-poms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-jaxr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-jaxrpc-api_1.1_spec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-jca-1.5-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-jms-1.1-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-jpa-deployers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-logbridge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-logmanager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-man");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-mdr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-messaging");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-metadata");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-microcontainer2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-naming");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-parent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-reflect");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-remoting");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-remoting-aspects");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-seam-int");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-seam2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-seam2-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-seam2-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-seam2-runtime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-security-aspects");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-security-negotiation");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-security-spi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-security-xacml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-serialization");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-specs-parent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-threads");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-transaction-1.0.1-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-transaction-aspects");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-vfs2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-xnio-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-xnio-metadata");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss5-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas-messaging511");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas-ws-cxf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas-ws-native");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbosssx2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossts-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossweb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossweb-el-1.0-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossweb-jsp-2.1-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossweb-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossweb-servlet-2.5-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossws-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossws-framework");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossws-parent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossws-spi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossxb2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jcip-annotations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jcommon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jdom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jettison");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jfreechart");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jgroups");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:joesnmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jopr-embedded");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jopr-hibernate-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jopr-jboss-as-5-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jopr-jboss-cache-v3-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:juddi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jyaml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:log4j");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_cluster-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_cluster-jbossas");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_cluster-jbossweb2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_cluster-native");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_cluster-tomcat6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_jk-ap20");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:msv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:msv-xsdlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mx4j");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:netty");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:objectweb-asm31");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:org-mc4j-ems");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:quartz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:regexp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:relaxngDatatype");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:resteasy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:resteasy-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:resteasy-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:resteasy-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eap-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eap-docs-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhq-ant-bundle-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhq-common-parent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhq-core-client-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhq-core-comm-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhq-core-dbutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhq-core-domain");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhq-core-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhq-core-native-system");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhq-core-parent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhq-core-plugin-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhq-core-plugin-container");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhq-core-plugindoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhq-core-util");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhq-filetemplate-bundle-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhq-helpers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhq-jboss-as-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhq-jmx-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhq-modules-parent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhq-parent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhq-platform-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhq-plugin-validator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhq-pluginAnnotations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhq-pluginGen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhq-plugins-parent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhq-rtfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:richfaces");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:richfaces-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:richfaces-framework");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:richfaces-root");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:richfaces-ui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:scannotation");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:servletapi4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:slf4j");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:slf4j-jboss-logging");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:snmptrapappender");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spring2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spring2-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spring2-aop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spring2-beans");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spring2-context");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spring2-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:stax-ex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sun-fi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sun-saaj-1.3-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sun-sjsxp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sun-ws-metadata-2.0-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sun-xmlstreambuffer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sun-xsom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat-native");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:velocity");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:werken-xpath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ws-commons-XmlSchema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ws-commons-axiom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ws-commons-neethi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ws-scout");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:wsdl4j16");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:wss4j");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:wstx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xalan-j2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xerces-j2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xerces-j2-scripts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xml-commons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xml-commons-jaxp-1.1-apis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xml-commons-jaxp-1.2-apis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xml-commons-jaxp-1.3-apis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xml-commons-resolver10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xml-commons-resolver11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xml-commons-resolver12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xml-commons-which10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xml-commons-which11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xml-security");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/07/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/24");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");
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
  rhsa = "RHSA-2011:0946";
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

  if (! (rpm_exists(release:"RHEL6", rpm:"jbossas-client-"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "JBoss EAP");

  if (rpm_check(release:"RHEL6", reference:"antlr-2.7.7-7.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"apache-cxf-2.2.12-3.patch_01.1.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"apache-james-0.6-6.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"avalon-framework-4.1.5-2.2.8.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"avalon-logkit-1.2-8.2.1.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"bcel-5.2-9.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"bsf-2.4.0-4.2.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"bsh-1.3.0-15.5.1.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"bsh2-2.0-0.b4.13.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"bsh2-bsf-2.0-0.b4.13.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"cglib-2.2-5.4.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"codehaus-jackson-1.3.5-0.1.1.2.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"codehaus-jackson-core-asl-1.3.5-0.1.1.2.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"codehaus-jackson-jaxrs-1.3.5-0.1.1.2.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"codehaus-jackson-mapper-asl-1.3.5-0.1.1.2.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"codehaus-stax-1.2.0-10.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"codehaus-stax-api-1.2.0-10.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"concurrent-1.3.4-10.1.5_jboss_update1.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"dom4j-1.6.1-11.1.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"dtdparser-1.21-6.2.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ecj3-3.3.1.1-4.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"facelets-1.1.15-1.B1.2.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"glassfish-jaf-1.1.0-8.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"glassfish-javamail-1.4.2-2.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"glassfish-jaxb-2.1.12-9.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"glassfish-jaxws-2.1.7-0.30.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"glassfish-jsf-1.2_13-3.1.4.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"glassfish-jstl-1.2.0-12.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"gnu-getopt-1.0.13-1.1.4.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"gnu-trove-1.0.2-7.1.3.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"hibernate3-3.3.2-1.8.GA_CP04.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"hibernate3-annotations-3.4.0-3.5.GA_CP04.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"hibernate3-annotations-javadoc-3.4.0-3.5.GA_CP04.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"hibernate3-commons-annotations-3.1.0-1.8.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"hibernate3-commons-annotations-javadoc-3.1.0-1.8.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"hibernate3-ejb-persistence-3.0-api-1.0.2-3.3.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"hibernate3-ejb-persistence-3.0-api-javadoc-1.0.2-3.3.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"hibernate3-entitymanager-3.4.0-4.4.GA_CP04.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"hibernate3-entitymanager-javadoc-3.4.0-4.4.GA_CP04.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"hibernate3-javadoc-3.3.2-1.8.GA_CP04.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"hibernate3-search-3.1.1-2.4.GA_CP04.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"hibernate3-search-javadoc-3.1.1-2.4.GA_CP04.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"hibernate3-validator-3.1.0-1.5.4.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"hibernate3-validator-javadoc-3.1.0-1.5.4.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"hornetq-jopr-plugin-2.0.0-1.Final.2.1.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"hsqldb-1.8.0.10-9_patch_01.2.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"i18nlog-1.0.10-6.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"isorelax-0-0.4.release20050331.2.4.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jacorb-jboss-2.3.1-9.patch02.2.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jakarta-commons-beanutils-1.8.0-9.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jakarta-commons-codec-1.3-12.1.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jakarta-commons-collections-3.2.1-4.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jakarta-commons-collections-tomcat5-3.2.1-4.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jakarta-commons-dbcp-1.2.1-16.2.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jakarta-commons-dbcp-tomcat5-1.2.1-16.2.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jakarta-commons-digester-1.8.1-8.1.1.1.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jakarta-commons-discovery-0.4-7.3.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jakarta-commons-el-1.0-19.2.1.1.ep5.el6")) flag++;
  if (rpm_exists(rpm:"jakarta-commons-httpclient-3.1-1", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"jakarta-commons-httpclient-3.1-1.2.2.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jakarta-commons-io-1.4-4.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jakarta-commons-lang-2.4-1.3.1.1.1.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jakarta-commons-logging-1.1.1-1.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jakarta-commons-logging-jboss-1.1-10.2.2.1.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jakarta-commons-parent-11-2.1.2.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jakarta-commons-pool-1.3-15.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jakarta-commons-pool-tomcat5-1.3-15.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jakarta-oro-2.0.8-7.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"javassist-3.12.0-3.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jaxbintros-1.0.0-3.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jaxen-1.1.2-8.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-aop2-2.1.6-1.CP02.1.3.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-aspects-build-1.0.1-0.CR5.1.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-aspects-common-1.0.0-0.b1.1.5.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-bootstrap-1.0.1-2.4.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-cache-core-3.2.7-5.1.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-cache-pojo-3.0.0-8.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-cl-2.0.9-1.3.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-cluster-ha-client-1.1.1-1.3.1.3.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-cluster-ha-server-api-1.2.0-1.1.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-cluster-ha-server-cache-jbc-2.0.3-1.3.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-cluster-ha-server-cache-spi-2.0.0-2.3.3.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-common-core-2.2.17-1.2.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-common-logging-jdk-2.1.2-1.2.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-common-logging-log4j-2.1.2-1.1.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-common-logging-spi-2.1.2-1.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-current-invocation-aspects-1.0.1-1.7.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-deployers-2.0.10-4.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i386", reference:"jboss-eap5-native-5.1.1-3.2.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jboss-eap5-native-5.1.1-3.2.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-ejb-3.0-api-5.0.1-2.9.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-ejb3-build-1.0.13-3.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-ejb3-cache-1.0.0-3.7.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-ejb3-common-1.0.2-0.4.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-ejb3-context-0.1.1-0.6.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-ejb3-context-base-0.1.1-0.6.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-ejb3-context-naming-0.1.1-0.6.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-ejb3-core-1.3.7-0.3.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-ejb3-deployers-1.1.4-0.5.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-ejb3-endpoint-0.1.0-2.4.3.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-ejb3-endpoint-deployer-0.1.4-1.4.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-ejb3-ext-api-1.0.0-3.7.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-ejb3-ext-api-impl-1.0.0-3.6.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-ejb3-interceptors-1.0.7-0.5.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-ejb3-jpa-int-1.0.0-1.3.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-ejb3-mc-int-1.0.2-1.3.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-ejb3-metadata-1.0.0-2.6.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-ejb3-metrics-deployer-1.1.0-0.4.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-ejb3-proxy-clustered-1.0.3-1.3.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-ejb3-proxy-impl-1.0.6-2.SP1.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-ejb3-proxy-spi-1.0.0-1.5.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-ejb3-security-1.0.2-0.4.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-ejb3-timeout-0.1.1-0.7.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-ejb3-timeout-3.0-api-0.1.1-0.7.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-ejb3-timeout-spi-0.1.1-0.7.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-ejb3-timerservice-spi-1.0.4-0.1.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-ejb3-transactions-1.0.2-1.5.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-ejb3-vfs-1.0.0-0.alpha1.0.3.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-ejb3-vfs-impl-vfs2-1.0.0-0.alpha1.0.3.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-ejb3-vfs-spi-1.0.0-0.alpha1.0.3.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-el-1.0_02-0.CR5.3.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-integration-5.1.0-2.SP1.5.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-jacc-1.1-api-5.0.1-2.9.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-jad-1.2-api-5.0.1-2.9.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-jaspi-1.0-api-5.0.1-2.9.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-javaee-5.0.1-2.9.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-javaee-poms-5.0.1-2.9.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-jaxr-2.0.1-7.1.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-jaxrpc-api_1.1_spec-1.0.0-15.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-jca-1.5-api-5.0.1-2.9.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-jms-1.1-api-5.0.1-2.9.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-jpa-deployers-1.0.0-1.4.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-logbridge-1.0.1-2.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-logmanager-1.1.2-3.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-man-2.1.1-4.SP2.6.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-mdr-2.0.3-1.1.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-messaging-1.4.8-6.SP1.1.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-metadata-1.0.6-2.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-microcontainer2-2.0.10-5.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-naming-5.0.3-2.6.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-parent-4.0-3.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-reflect-2.0.3-7.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-remoting-2.5.4-8.SP2.1.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-remoting-aspects-1.0.3-0.6.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-seam-int-5.1.0-2.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-seam2-2.2.4.EAP5-3.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-seam2-docs-2.2.4.EAP5-3.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-seam2-examples-2.2.4.EAP5-3.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-seam2-runtime-2.2.4.EAP5-3.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-security-aspects-1.0.0-2.4.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-security-negotiation-2.0.3-2.SP3.3.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-security-spi-2.0.4-5.SP7.1.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-security-xacml-2.0.5-3.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-serialization-1.0.5-2.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-specs-parent-1.0.0-0.3.Beta2.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-threads-1.0.0-2.3.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-transaction-1.0.1-api-5.0.1-2.9.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-transaction-aspects-1.0.0-1.6.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-vfs2-2.2.0-4.SP1.3.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-xnio-base-1.2.1-6.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-xnio-metadata-1.0.1-1.4.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss5-libs-5.1.0-1.6.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jbossas-5.1.1-17.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jbossas-client-5.1.1-17.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jbossas-messaging511-5.1.1-17.4.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jbossas-ws-cxf-5.1.1-6.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jbossas-ws-native-5.1.1-17.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jbosssx2-2.0.4-5.SP7.2.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jbossts-4.6.1-10.CP11_patch_01.3.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jbossts-javadoc-4.6.1-10.CP11_patch_01.3.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jbossweb-2.1.11-5.4.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jbossweb-el-1.0-api-2.1.11-5.4.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jbossweb-jsp-2.1-api-2.1.11-5.4.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jbossweb-lib-2.1.11-5.4.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jbossweb-servlet-2.5-api-2.1.11-5.4.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jbossws-3.1.2-6.SP10.1.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jbossws-common-1.1.0-3.SP7.1.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jbossws-framework-3.1.2-5.SP9.2.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jbossws-parent-1.0.8-2.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jbossws-spi-1.1.2-4.SP6.1.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jbossxb2-2.0.1-8.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jcip-annotations-1.0-2.2.2.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jcommon-1.0.16-1.2.2.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jdom-1.1.1-2.1.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jettison-1.2-3.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jfreechart-1.0.13-2.3.2.1.2.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jgroups-2.6.19-2.1.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"joesnmp-0.3.4-3.2.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jopr-embedded-1.3.4-17.SP4.8.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jopr-hibernate-plugin-3.0.0-11.EmbJopr3.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jopr-jboss-as-5-plugin-3.0.0-10.EmbJopr3.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jopr-jboss-cache-v3-plugin-3.0.0-9.EmbJopr3.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"juddi-2.0.1-4.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jyaml-1.3-3.3.2.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"log4j-1.2.14-18.2.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"mod_cluster-demo-1.0.10-2.2.GA_CP01.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"mod_cluster-jbossas-1.0.10-2.2.GA_CP01.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"mod_cluster-jbossweb2-1.0.10-2.2.GA_CP01.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i386", reference:"mod_cluster-native-1.0.10-2.1.1.GA_CP01.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"mod_cluster-native-1.0.10-2.1.1.GA_CP01.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"mod_cluster-tomcat6-1.0.10-2.2.GA_CP01.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i386", reference:"mod_jk-ap20-1.2.31-1.1.2.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"mod_jk-ap20-1.2.31-1.1.2.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"msv-1.2-0.20050722.10.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"msv-xsdlib-1.2-0.20050722.10.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"mx4j-3.0.1-12.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"netty-3.2.3-5.3.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"objectweb-asm31-3.1-12.1.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"org-mc4j-ems-1.2.15.1-4.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"quartz-1.5.2-6.6.patch01.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"regexp-1.5-5.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"relaxngDatatype-1.0-2.4.4.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"resteasy-1.2.1-8.CP01.8.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"resteasy-examples-1.2.1-8.CP01.8.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"resteasy-javadoc-1.2.1-8.CP01.8.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"resteasy-manual-1.2.1-8.CP01.8.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rh-eap-docs-5.1.1-6.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rh-eap-docs-examples-5.1.1-6.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rhq-3.0.0-17.EmbJopr3.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rhq-ant-bundle-common-3.0.0-17.EmbJopr3.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rhq-common-parent-3.0.0-17.EmbJopr3.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rhq-core-client-api-3.0.0-17.EmbJopr3.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rhq-core-comm-api-3.0.0-17.EmbJopr3.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rhq-core-dbutils-3.0.0-17.EmbJopr3.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rhq-core-domain-3.0.0-17.EmbJopr3.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rhq-core-gui-3.0.0-17.EmbJopr3.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rhq-core-native-system-3.0.0-17.EmbJopr3.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rhq-core-parent-3.0.0-17.EmbJopr3.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rhq-core-plugin-api-3.0.0-17.EmbJopr3.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rhq-core-plugin-container-3.0.0-17.EmbJopr3.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rhq-core-plugindoc-3.0.0-17.EmbJopr3.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rhq-core-util-3.0.0-17.EmbJopr3.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rhq-filetemplate-bundle-common-3.0.0-17.EmbJopr3.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rhq-helpers-3.0.0-17.EmbJopr3.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rhq-jboss-as-common-3.0.0-17.EmbJopr3.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rhq-jmx-plugin-3.0.0-15.EmbJopr3.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rhq-modules-parent-3.0.0-17.EmbJopr3.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rhq-parent-3.0.0-17.EmbJopr3.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rhq-platform-plugin-3.0.0-12.EmbJopr3.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rhq-plugin-validator-3.0.0-17.EmbJopr3.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rhq-pluginAnnotations-3.0.0-17.EmbJopr3.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rhq-pluginGen-3.0.0-17.EmbJopr3.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rhq-plugins-parent-3.0.0-17.EmbJopr3.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rhq-rtfilter-3.0.0-17.EmbJopr3.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"richfaces-3.3.1-1.SP3.1.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"richfaces-demo-3.3.1-1.SP3.1.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"richfaces-framework-3.3.1-1.SP3.1.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"richfaces-root-3.3.1-1.SP3.1.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"richfaces-ui-3.3.1-1.SP3.1.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"scannotation-1.0.2-3.2.1.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"servletapi4-4.0.4-6.2.1.3.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"slf4j-1.5.8-8.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"slf4j-jboss-logging-1.0.3-1.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"snmptrapappender-1.2.8-8.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"spring2-2.5.6-8.SEC02.4.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"spring2-agent-2.5.6-8.SEC02.4.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"spring2-aop-2.5.6-8.SEC02.4.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"spring2-beans-2.5.6-8.SEC02.4.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"spring2-context-2.5.6-8.SEC02.4.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"spring2-core-2.5.6-8.SEC02.4.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"stax-ex-1.2-11.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"sun-fi-1.2.7-6.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"sun-saaj-1.3-api-1.3-6.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"sun-sjsxp-1.0.1-5.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"sun-ws-metadata-2.0-api-1.0.MR1-11.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"sun-xmlstreambuffer-0.8-1.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"sun-xsom-20070515-4.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i386", reference:"tomcat-native-1.1.20-2.1.2.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"tomcat-native-1.1.20-2.1.2.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"velocity-1.6.3-1.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"werken-xpath-0.9.4-4.beta.13.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ws-commons-XmlSchema-1.4.5-2.4.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ws-commons-axiom-1.2.7-3.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ws-commons-neethi-2.0.4-1.2.2.3.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ws-scout-1.1.1-3.4.3.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"wsdl4j16-1.6.2-7.5.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"wss4j-1.5.10-3_patch_01.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"wstx-3.2.9-1.5.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"xalan-j2-2.7.1-5.3_patch_04.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"xerces-j2-2.9.1-8.patch01.1.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"xerces-j2-scripts-2.9.1-8.patch01.1.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"xml-commons-1.3.04-7.14.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"xml-commons-jaxp-1.1-apis-1.3.04-7.14.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"xml-commons-jaxp-1.2-apis-1.3.04-7.14.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"xml-commons-jaxp-1.3-apis-1.3.04-7.14.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"xml-commons-resolver10-1.3.04-7.14.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"xml-commons-resolver11-1.3.04-7.14.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"xml-commons-resolver12-1.3.04-7.14.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"xml-commons-which10-1.3.04-7.14.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"xml-commons-which11-1.3.04-7.14.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"xml-security-1.4.3-6.ep5.el6")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "antlr / apache-cxf / apache-james / avalon-framework / etc");
  }
}
