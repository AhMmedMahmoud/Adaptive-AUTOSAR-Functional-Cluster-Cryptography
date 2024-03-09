#include <string>
#include <vector>
#include "instance_specifier.h"
#include <functional>
#include <string>
#include <iostream>
using namespace std;

#ifndef ARA_COM_INSTANCE_IDENTIFIER_H
#define ARA_COM_INSTANCE_IDENTIFIER_H
namespace ara
{
    namespace com
    {
        /**
         * \addtogroup runtime
         *
         * @{
         */

         /**
          * \brief Identifier of a certain instance of a service.
          *
          * \uptrace{SWS_CM_00302, ac1760b912647e7c7e4566c0e30a818b0174002f}
          */
        class InstanceIdentifier
        {
        private:
            string instance_id_;
        public:
            explicit InstanceIdentifier(string value)
                : instance_id_(value)
            { }
            string ToString() const
            {
                return instance_id_;
            }
            uint16_t getInstanceId()
            {
                return std::stoi(instance_id_);
            }


            bool operator==(const InstanceIdentifier& other) const
            {
                return instance_id_ == other.instance_id_;
            }
            bool operator<(const InstanceIdentifier& other) const
            {
                return instance_id_ < other.instance_id_;
            }
            InstanceIdentifier(const InstanceIdentifier&) = default;
            InstanceIdentifier(InstanceIdentifier&&) = default;
            InstanceIdentifier& operator=(const InstanceIdentifier&) = default;
            InstanceIdentifier& operator=(InstanceIdentifier&&) = default;
            ~InstanceIdentifier() = default;

            bool IsAny() const noexcept
            {
                return instance_id_.size() >= 3 && instance_id_.substr(instance_id_.size() - 3, 3) == ANY();
            }

            static InstanceIdentifier MakeAny() noexcept
            {
                static const InstanceIdentifier any(ANY());
                return any;
            }
            // Due to limitations of C++14 use static const method ANY() instead of defining class constant:
            // static constexpr char ANY[] = "ANY";
            // Reason: every transport implements it's own cpp files, and in one of them it will have to add string:
            // constexpr char InstanceIdentifier::ANY[];
            //
            // This is used during service discovery for \see FindService or \see StartFindService.
            static const char* ANY()
            {
                static const char any[] = "ANY";
                return any;
            }
        };

        using InstanceIdentifierContainer = vector<InstanceIdentifier>;

        namespace runtime
        {
            InstanceIdentifierContainer ResolveInstanceIDs(ara::core::InstanceSpecifier modelName);
        }
    }
}

namespace std
{

    template <>
    struct hash<ara::com::InstanceIdentifier>
    {
    public:
        using result_type = std::size_t;
        using argument_type = ara::com::InstanceIdentifier;
        /**
         * \brief function-call operator to retrieve the hash value of InstanceIdentifier.
         *
         * By providing this, InstanceIdentifier can be used in std::unordered_map and std::unordered_set.
         *
         * \param id InstanceIdentifier to be hashed.
         * \return Hash value.
         */
        std::size_t operator()(const ara::com::InstanceIdentifier& id) const
        {
            string s(id.ToString());
            return std::hash<string>()(s);
        }
    };

}  // namespace std

#endif  // ARA_COM_INSTANCE_IDENTIFIER_H