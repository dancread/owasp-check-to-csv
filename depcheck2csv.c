#include <stdio.h>
#include <libxml/xmlreader.h>
//#include <libxml/xmlversion.h>
#include <libxml/xmlmemory.h>
#include <libxml/parser.h>

void parseProjectName(xmlDocPtr, xmlNodePtr);
void parseDependencies(xmlDocPtr, xmlNodePtr);
void parseVulnerabilities(xmlDocPtr, xmlNodePtr);
void parseVulnerability(xmlDocPtr, xmlNodePtr);
void parseSeverity(xmlDocPtr, xmlNodePtr);
/* CSV entries:
  project name
  report date
  dependency name
  vulnerability
  severity
*/
int main(){
  xmlDocPtr    xml_doc = xmlParseFile("dependency-check-report.xml");
  xmlNodePtr   xml_cur_node = xmlDocGetRootElement(xml_doc);
  //LIBXML_TEST_VERSION;
  printf("%s\n", xml_cur_node->children->content);
  xml_cur_node = xml_cur_node->xmlChildrenNode;
  while (xml_cur_node != NULL) {
      // Get project info
      if ((!xmlStrcmp(xml_cur_node->name, (const xmlChar *)"projectInfo"))){
        printf("%s\n", xml_cur_node->name);
        parseProjectName(xml_doc, xml_cur_node);
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
void parseProjectName(xmlDocPtr xml_doc, xmlNodePtr xml_ptr){
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
        parseVulnerabilities(xml_doc, xml_ptr);
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
    xml_ptr = xml_ptr->xmlChildrenNode;
    // Get vulnerability
    while (xml_ptr != NULL) {
      //printf("%s\n", xml_ptr->name);
	    if ((!xmlStrcmp(xml_ptr->name, (const xmlChar *)"severity"))) {
        severity = xmlNodeListGetString(xml_doc, xml_ptr->xmlChildrenNode, 1);
		    printf("%s\n", severity);
		    xmlFree(severity);
      }
      xml_ptr = xml_ptr->next;
    }

}
