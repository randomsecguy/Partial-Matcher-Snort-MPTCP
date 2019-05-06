#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>
#include <sys/types.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <unistd.h>

#include "main/snort.h"
#include "detection/detect.h"
#include "main/snort_debug.h"
#include "main/snort_types.h"
//#include "main/snort.h"
#include "events/event_queue.h"
#include "framework/inspector.h"
#include "framework/module.h"
#include "log/messages.h"
#include "protocols/packet.h"
#include "protocols/tcp.h"
#include "protocols/tcp_options.h"
#include "protocols/udp.h"
#include "profiler/profiler.h"
#include "utils/stats.h"

#include "proto/seg_xfer.pb.h"
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>


#define MPTCP_STREAM_GID 256
#define MPTCP_STREAM_SID 1
#define MPTCP 0x1e


static const char* s_name = "mptcp_stream";
static const char* s_help = "dynamic inspector example";


static const char *socket_path = "/home/cxa/Desktop/socket";


static THREAD_LOCAL ProfileStats mptcp_streamPerfStats;

static THREAD_LOCAL SimpleStats mptcp_streamstats;

THREAD_LOCAL Packet * mp_pkt;

const char* trigger_buff = "FIREFIREFIRE\n"; // for testing

int packet_count = 0;
int mptcp_count= 0;

//-------------------------------------------------------------------------
// class stuff
//-------------------------------------------------------------------------

class Mptcp_stream : public Inspector
{
public:
    Mptcp_stream(uint16_t port, uint16_t max);

    void show(SnortConfig*) override;
    void eval(Packet*) override;

private:
    uint16_t port;
    uint16_t max;
};

Mptcp_stream::Mptcp_stream(uint16_t p, uint16_t m)
{   
    	
    LogMessage("Mptcp_stream Constructor??");
    port = p;
    max = m;
}

void Mptcp_stream::show(SnortConfig*)
{
    LogMessage("%s config:\n", s_name);
    LogMessage("    port = %d\n", port);
    LogMessage("    max = %d\n", max);
    LogMessage("Mptcp_stream Show\n");
}



void Mptcp_stream::eval(Packet* p)
{
    packet_count++;
    printf("Packet Count: %d\n", packet_count);
    
    assert(p->is_tcp());
    
    /* Build the PROTOBUF */
    seg_xfer::PacketMsg segment_msg;
    seg_xfer::ReassembledPayload reassembled_payload;

    segment_msg.set_name("From Snort");
    mp_pkt = new Packet();

      
   uint32_t sip;
   sip = p->ptrs.ip_api.get_src()->get_ip4_value();  
   struct in_addr ip_addr;
   ip_addr.s_addr = sip;
   std::string srcip = inet_ntoa(ip_addr);

   
   uint32_t dip;
   dip = p->ptrs.ip_api.get_dst()->get_ip4_value();  
   struct in_addr ip_addr1;
   ip_addr1.s_addr = dip;
   std::string dstip = inet_ntoa(ip_addr1);
  
    
   int srcprt=p->ptrs.tcph->src_port();
   int dstprt=p->ptrs.tcph->dst_port();
   


   printf("MSG FROM %s:%d -> %s:%d\n ", srcip.c_str(), srcprt, dstip.c_str(), dstprt );

  

   //printf("Pkt has flag: %x\n", p->ptrs.tcph->th_flags);
   
    
   //if ( p->ptrs.tcph->is_psh() )
   //{
   // printf("Data pkt sent from snort");
  // }

   //if ( p->ptrs.tcph->th_flags== TH_SYN & TH_ACK )
   //{
    //printf("Pkt has SYN and ACK");
   //}

  
    int mptcp_flag=0;
    tcp::TcpOptIterator iter1(p->ptrs.tcph, p);
    for ( const tcp::TcpOption& opt : iter1 )
    {
        if ( (std::uint8_t) opt.code == MPTCP ) /* 0x1e == MPTCP */
        {
            mptcp_flag=1;
        }
    }
    //check if packet has an MPTCP option. If so continue on with MPTCP processing, otherwise pass packet directly to Snort
    if (mptcp_flag==1) {
    
    mptcp_count++;   
   
  
    segment_msg.set_src_ip( p->ptrs.ip_api.get_src()->get_ip4_value()); // only IPv4 Right now
    segment_msg.set_dst_ip( p->ptrs.ip_api.get_dst()->get_ip4_value());
    segment_msg.set_src_port(p->ptrs.tcph->src_port());
    segment_msg.set_dst_port(p->ptrs.tcph->dst_port());
    segment_msg.set_seqno( (uint32_t) p->ptrs.tcph->seq());
    segment_msg.set_ackno( (uint32_t) p->ptrs.tcph->ack());
    segment_msg.set_tcp_flags(p->ptrs.tcph->th_flags);
    segment_msg.set_payload((char *) p->data, p->dsize);
    segment_msg.set_dsize(p->dsize);
    

    

    /* Report MPTCP Options */
    tcp::TcpOptIterator iter(p->ptrs.tcph, p);
    for ( const tcp::TcpOption& opt : iter )
    {
        if ( (std::uint8_t) opt.code == MPTCP ) /* 0x1e == MPTCP */
        {
            segment_msg.add_mptcp_option(opt.data, opt.len);
        }
    }


    struct sockaddr_un addr;
    char buf[100];
    int fd,rc;

    if ( (fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        perror("socket error");
        exit(-1);
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path)-1);

    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
        perror("connect error");
        exit(-1);
    }

   
    segment_msg.SerializeToFileDescriptor(fd);


    reassembled_payload.ParseFromFileDescriptor(fd);


    close(fd);


    mp_pkt->ptrs.set_pkt_type(PktType::PDU);
    mp_pkt->flow = p->flow;  // Need to figure out how to prevent multiple alerts being generated from same traffic
    mp_pkt->proto_bits |= PROTO_BIT__TCP;

    mp_pkt->ptrs.ip_api.set(*p->ptrs.ip_api.get_dst(),
                            *p->ptrs.ip_api.get_src());
    mp_pkt->ptrs.dp = p->ptrs.sp;
    mp_pkt->ptrs.sp = p->ptrs.dp;

       
    
//Here comes the code that sends recreated datastream + info to Slicedistance python program. If a match is returned, we replace the payload
//with what is returned 

    if ( p->ptrs.tcph->is_psh() ) //not sure if this is a good check. maybe mptcp pkts flow on other flags too
    {
     
    
    

    std::string ftuple= srcip.c_str() + std::string(":") + std::to_string(srcprt) + std::string(" > ") + dstip.c_str() + std::string(":") + std::to_string(dstprt)  ; 


    std::string depth = std::to_string(reassembled_payload.payload().length());

     


    std::string commandline = std::string("python /home/cxa/Desktop/slice_distances/test_allhex.py ") + std::string("'") +  std::string(reassembled_payload.payload().data()) + std::string("'") + std::string(" '") + ftuple + std::string("'") + std::string(" '") + depth + std::string("'");

  
    std::array<char, 128> buffer;
    std::string result;
    std::shared_ptr<FILE> pipe(popen(commandline.c_str(), "r"), pclose);
    if (!pipe) throw std::runtime_error("popen() failed!");
    while (!feof(pipe.get())) {
        if (fgets(buffer.data(), 128, pipe.get()) != nullptr)
            result += buffer.data();
    }

   int len= result.size();
    
   if (len==0) {
     printf("No match in MATCHER for [%s]!!!\n", reassembled_payload.payload().data()); 
     mp_pkt->data = (uint8_t *) reassembled_payload.payload().data();
     mp_pkt->dsize = reassembled_payload.payload().length();
     printf("Sending to snort[%s]", mp_pkt->data);
     printf("snort_detect result=%d\n", snort_detect(mp_pkt));
     //sleep(15);

    }


   //Code to use result from matcher and update pkt before sending it to snort for detection 

    if (len > 0) { //If matcher returns match/es

    //printf("size%d",result.size());
    result.erase(std::remove(result.begin(), result.end(), '\n'), result.end());//delete new line

    printf("Sent text [%s],  matched pattern [%s], ", reassembled_payload.payload().data(), result.c_str());  

    //result.erase(std::remove(result.begin(), result.end(), '\n'), result.end());  //delete new line

    int n = std::count(result.begin(), result.end(), ';');
  
    if (n==0){          //matcher returns two possible matches with a | between them
   
    printf("Only one matched pattern, ");
    //printf("Slicing string1:%s\n", result.substr(0, pos).c_str());
    //printf("Slicing string2:%s\n", result.substr(pos + 1).c_str());
 
    
    mp_pkt->data = (uint8_t *) result.c_str();
    mp_pkt->dsize = result.length();
    printf("Sending pkt with [%s] to snort", mp_pkt->data);
    printf("snort_detect result=%d\n", snort_detect(mp_pkt));}//if(n==0)
     
    if(n==1){
  
    printf("At least two matched patterns, ");
    int pos = result.find(";");

    mp_pkt->data = (uint8_t *) result.substr(0, pos).c_str();
    mp_pkt->dsize = result.substr(0, pos).length();
    printf("Sending pkt with [%s] to snort", mp_pkt->data);
    printf("snort_detect result=%d\n", snort_detect(mp_pkt));
    

    mp_pkt->data = (uint8_t *) result.substr(pos + 1).c_str();
    mp_pkt->dsize = result.substr(pos + 1).length();
    printf("Sending pkt with [%s] to snort", mp_pkt->data);
    printf("snort_detect result=%d\n", snort_detect(mp_pkt));}//if(n==1)
 
    if(n>1){
     
     printf("Too many matched patterns!!N=[%d]\n", n+1);      
     std::string delimiter = ";";

     size_t pos1 = 0;
     std::string token;
     while ((pos1 = result.find(delimiter)) != std::string::npos) {
      token = result.substr(0, pos1);
      //std::cout << token << std::endl;
      mp_pkt->data = (uint8_t *) token.c_str();
      mp_pkt->dsize = token.length();
      printf("Sending pkt with [%s] to snort", mp_pkt->data);
      printf("snort_detect result=%d\n", snort_detect(mp_pkt));


      result.erase(0, pos1 + delimiter.length());}//while loop

      token = result.substr(pos1 +1);      
      mp_pkt->data = (uint8_t *) token.c_str();
      mp_pkt->dsize = token.length();
      printf("Sending pkt with [%s] to snort", mp_pkt->data);
      printf("snort_detect result=%d\n", snort_detect(mp_pkt)); }//if(n>1)

    

}//If matcher returns match/es

}//if its a datapacket

    if ( p->ptrs.dp == port && p->dsize > max )
        SnortEventqAdd(MPTCP_STREAM_GID, MPTCP_STREAM_SID);

    ++mptcp_streamstats.total_packets;


    }//end of loop that checks if packet is MPTCP or not
    else {
          printf("Not MPTCP (pass to snort directly) "); 
          printf("snort_detect result=%d\n", snort_detect(p));}

printf("Total MPTCP packets:%d\n\n", mptcp_count);
}//end of eval

//-------------------------------------------------------------------------
// module stuff
//-------------------------------------------------------------------------

static const Parameter mptcp_stream_params[] =
{
    { "port", Parameter::PT_PORT, nullptr, nullptr,
      "port to check" },

    { "max", Parameter::PT_INT, "0:65535", "0",
      "maximum payload before alert" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const RuleMap mptcp_stream_rules[] =
{
    { MPTCP_STREAM_SID, "too much data sent to port" },
    { 0, nullptr }
};

class Mptcp_streamModule : public Module
{
public:
    Mptcp_streamModule() : Module(s_name, s_help, mptcp_stream_params)
    { }

    unsigned get_gid() const override
    { return MPTCP_STREAM_GID; }

    const RuleMap* get_rules() const override
    { return mptcp_stream_rules; }

    const PegInfo* get_pegs() const override
    { return simple_pegs; }

    PegCount* get_counts() const override
    { return (PegCount*)&mptcp_streamstats; }

    ProfileStats* get_profile() const override
    { return &mptcp_streamPerfStats; }

    bool set(const char*, Value& v, SnortConfig*) override;

public:
    uint16_t port;
    uint16_t max;
};

bool Mptcp_streamModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("port") )
        port = v.get_long();

    else if ( v.is("max") )
        max = v.get_long();

    else
        return false;

    return true;
}

//-------------------------------------------------------------------------
// api stuff
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new Mptcp_streamModule; }

static void mod_dtor(Module* m)
{ delete m; }

static Inspector* mptcp_stream_ctor(Module* m)
{
    Mptcp_streamModule* mod = (Mptcp_streamModule*)m;
    return new Mptcp_stream(mod->port, mod->max);
}

static void mptcp_stream_dtor(Inspector* p)
{
    delete p;
}

static const InspectApi mptcp_stream_api
{
    {
        PT_INSPECTOR,
        sizeof(InspectApi),
        INSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        s_name,
        s_help,
        mod_ctor,
        mod_dtor
    },
    IT_PACKET,   // changed from IT_NETWORK
    (uint16_t)PktType::TCP,     // HF: Change this from DPX example to UDP
    nullptr, // buffers
    nullptr, // service
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    mptcp_stream_ctor,
    mptcp_stream_dtor,
    nullptr, // ssn
    nullptr  // reset
};

SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &mptcp_stream_api.base,
    nullptr
};

