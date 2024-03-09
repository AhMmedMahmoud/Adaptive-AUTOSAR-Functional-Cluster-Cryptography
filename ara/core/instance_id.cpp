#include "instance_id.h"
#include "instance_specifier.h"
#include <map>
using namespace std;


namespace
{

    struct InstanceSpecifier2ServiceInstance
    {
        string instanceSpecifier_;
        string serviceInstance_;
    };

    struct ServiceInstance2InstanceIdentifier
    {
        string serviceInstance_;
        string instanceIdentifier_;
    };


    map<ara::core::InstanceSpecifier, ara::com::InstanceIdentifierContainer> InitializeTranslations()
    {
        ara::com::InstanceIdentifierContainer c1;
        ara::com::InstanceIdentifier id1("1");
        c1.push_back(id1);
        ara::com::InstanceIdentifier id2("2");
        c1.push_back(id2);
        ara::com::InstanceIdentifier id3("3");
        c1.push_back(id3);

        ara::com::InstanceIdentifierContainer c2;
        ara::com::InstanceIdentifier id4("1");
        c2.push_back(id4);
        ara::com::InstanceIdentifier id5("2");
        c2.push_back(id5);
        ara::com::InstanceIdentifier id6("3");
        c2.push_back(id6);

        ara::com::InstanceIdentifierContainer c3;
        ara::com::InstanceIdentifier id7("1");
        c3.push_back(id7);
        ara::com::InstanceIdentifier id8("2");
        c3.push_back(id8);
        ara::com::InstanceIdentifier id9("3");
        c3.push_back(id9);

        ara::com::InstanceIdentifierContainer c4;
        ara::com::InstanceIdentifier id10("1");
        c4.push_back(id10);
        ara::com::InstanceIdentifier id11("2");
        c4.push_back(id11);
        ara::com::InstanceIdentifier id12("3");
        c4.push_back(id12);

        ara::core::InstanceSpecifier s1("trigger_in");
        ara::core::InstanceSpecifier s2("trigger_out");
        ara::core::InstanceSpecifier s3("trigger_in_out");
        ara::core::InstanceSpecifier s4("update_request");
        map<ara::core::InstanceSpecifier, ara::com::InstanceIdentifierContainer> data{

            {s1,c1},
            {s2,c2},
            {s3,c3},
            {s4,c4}
        };

        return data;

    }
}
namespace ara {
    namespace com {
        namespace runtime
        {
            /// @uptrace{SWS_CM_00118, 5cd0d8c4d73c76f3e44398cf89895c3f9e11a403}
            InstanceIdentifierContainer ResolveInstanceIDs(ara::core::InstanceSpecifier modelName)
            {
                map<ara::core::InstanceSpecifier, InstanceIdentifierContainer> m = InitializeTranslations();
                return m.at(modelName);

            }


        }  // runtime namespace

    } //com namespace
}//ara namespace
