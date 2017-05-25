#include <stdio.h>
#include <libxml/xmlreader.h>
//#include <libxml/xmlversion.h>
#include <libxml/xmlmemory.h>
#include <libxml/parser.h>

void parseProject(xmlDocPtr, xmlNodePtr);
void parseDependencies(xmlDocPtr, xmlNodePtr);
void parseVulnerabilities(xmlDocPtr, xmlNodePtr);
void parseVulnerability(xmlDocPtr, xmlNodePtr);
void parseSeverity(xmlDocPtr, xmlNodePtr);
void parseFileName(xmlDocPtr, xmlNodePtr);
/* CSV entries:
  project name
  report date
  dependency name
  vulnerability
  severity
*/
struct project_entry {
  xmlChar *project_name;
  xmlChar *report_date;
  xmlChar *dependency_name;
  xmlChar *vulnerability;
  xmlChar *severity;
};
int main(){
  struct project_entry;
  xmlDocPtr    xml_doc = xmlParseFile("dependency-check-report.xml");
  xmlNodePtr   xml_cur_node = xmlDocGetRootElement(xml_doc);
  //LIBXML_TEST_VERSION;
  printf("%s\n", xml_cur_node->children->content);
  xml_cur_node = xml_cur_node->xmlChildrenNode;
  while (xml_cur_node != NULL) {
      // Get project info
      if ((!xmlStrcmp(xml_cur_node->name, (const xmlChar *)"projectInfo"))){
        parseProject(xml_doc, xml_cur_node);
      }
      // Get dependencies with vulnerabilities
      if ((!xmlStrcmp(xml_cur_node->name, (const xmlChar *)"dependencies"))){
        parseDependencies(xml_doc, xml_cur_node);
      }
      xml_cur_node = xml_cur_node->next;
  }
  xmlFreeDoc(xml_doc);
  return 0;
}
void parseProject(xmlDocPtr xml_doc, xmlNodePtr xml_ptr){
    xmlChar *project_name;
    xml_ptr = xml_ptr->xmlChildrenNode;
    // Get project name
    while (xml_ptr != NULL) {
	    if ((!xmlStrcmp(xml_ptr->name, (const xmlChar *)"name"))) {
        project_name = xmlNodeListGetString(xml_doc, xml_ptr->xmlChildrenNode, 1);
        printf("project name: %s\n", project_name);
        xmlFree(project_name);
      }
      xml_ptr = xml_ptr->next;
    }
}
void parseDependencies(xmlDocPtr xml_doc, xmlNodePtr xml_ptr){
    xml_ptr = xml_ptr->xmlChildrenNode;
    
    // Get dependencies 
    while (xml_ptr != NULL) {
	    if ((!xmlStrcmp(xml_ptr->name, (const xmlChar *)"dependency"))) {
        parseFileName(xml_doc, xml_ptr);
        parseVulnerabilities(xml_doc, xml_ptr);
      }
      xml_ptr = xml_ptr->next;
    }
}
void parseFileName(xmlDocPtr xml_doc, xmlNodePtr xml_ptr){
    xmlChar *file_name;
    xml_ptr = xml_ptr->xmlChildrenNode;
    // Get file name
    while (xml_ptr != NULL) {
      //printf("%s\n", xml_ptr->name);
	    if ((!xmlStrcmp(xml_ptr->name, (const xmlChar *)"fileName"))) {
        file_name = xmlNodeListGetString(xml_doc, xml_ptr->xmlChildrenNode, 1);
		    printf("%s\n", file_name);
		    xmlFree(file_name);
      }
      xml_ptr = xml_ptr->next;
    }

}
void parseVulnerabilities(xmlDocPtr xml_doc, xmlNodePtr xml_ptr){
    xml_ptr = xml_ptr->xmlChildrenNode;
    // Get vulnerabilities
    while (xml_ptr != NULL) {
	    if ((!xmlStrcmp(xml_ptr->name, (const xmlChar *)"vulnerabilities"))) {
        parseVulnerability(xml_doc, xml_ptr);
      }
      xml_ptr = xml_ptr->next;
    }

}
void parseVulnerability(xmlDocPtr xml_doc, xmlNodePtr xml_ptr){
    xml_ptr = xml_ptr->xmlChildrenNode;
    // Get vulnerability
    while (xml_ptr != NULL) {
      //printf("%s\n", xml_ptr->name);
	    if ((!xmlStrcmp(xml_ptr->name, (const xmlChar *)"vulnerability"))) {
        parseSeverity(xml_doc, xml_ptr);
      }
      xml_ptr = xml_ptr->next;
    }

}
void parseSeverity(xmlDocPtr xml_doc, xmlNodePtr xml_ptr){
    xmlChar *severity;
    xmlChar *name;
    xml_ptr = xml_ptr->xmlChildrenNode;
    // Get severity
    while (xml_ptr != NULL) {
      //printf("%s\n", xml_ptr->name);
	    if ((!xmlStrcmp(xml_ptr->name, (const xmlChar *)"severity"))) {
        severity = xmlNodeListGetString(xml_doc, xml_ptr->xmlChildrenNode, 1);
		    printf("\t%s\n", severity);
		    xmlFree(severity);
      }
	    if ((!xmlStrcmp(xml_ptr->name, (const xmlChar *)"name"))) {
        name = xmlNodeListGetString(xml_doc, xml_ptr->xmlChildrenNode, 1);
		    printf("\t%s\n", name);
		    xmlFree(name);
      }
      xml_ptr = xml_ptr->next;
    }

}
