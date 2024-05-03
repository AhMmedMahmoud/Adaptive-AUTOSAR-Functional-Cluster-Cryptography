#include <iostream>
#include <vector>
#include <rapidjson/document.h>
#include <rapidjson/filereadstream.h>
#include "../ara/crypto/private/keys/key_slot_prototype_props.h"

using namespace ara::crypto::keys;
using namespace ara::crypto;

/*
struct KeySlotPrototypeProps
{
    using Uptr = std::unique_ptr<KeySlotPrototypeProps>;
    
    CryptoAlgId mAlgId;
    AllowedUsageFlags mContentAllowedUsage;
    CryptoObjectType mObjectType;
    bool mExportAllowed;
    KeySlotType mSlotType;
    std::size_t mSlotCapacity;
    bool mAllocateSpareSlot;
    bool mAllowContentTypeChange;
    std::int32_t mMaxUpdateAllowed;

    KeySlotPrototypeProps ()=default;
};
*/

struct CryptoKeySlotInterface
{
    std::string specifier;
    std::string CryptoProviderName;
    std::string CryptoObjectPath;
    KeySlotPrototypeProps pro;
};

std::vector<CryptoKeySlotInterface> parseManifest() 
{
    FILE* file = fopen("../ara/crypto/public/keys/manifest.json", "r");
    char buffer[65536];
    rapidjson::FileReadStream is(file, buffer, sizeof(buffer));

    rapidjson::Document document;
    document.ParseStream(is);

    std::vector<CryptoKeySlotInterface> KeySlotsMetaData;

    if (document.IsArray()) 
    {
        for (int i = 0; i < document.Size(); i++) 
        {
            const rapidjson::Value& obj = document[i];
            if (obj.IsObject()) 
            {
                CryptoKeySlotInterface Inteface;
                Inteface.specifier = obj["InstanceSpecifier"].GetString();
                Inteface.CryptoProviderName = obj["CryptoProvider"].GetString();
                Inteface.CryptoObjectPath = obj["KeyMaterialPath"].GetString();

                Inteface.pro.mAlgId = obj["ALgId"].GetInt();
                Inteface.pro.mContentAllowedUsage = obj["AllowUsageFlags"].GetInt();

                std::string ObjectType = obj["CryptoObjectType"].GetString();
                if(ObjectType == "kPrivateKey")
                    Inteface.pro.mObjectType = CryptoObjectType::kPrivateKey;
                else if(ObjectType == "kPublicKey")
                  Inteface.pro.mObjectType = CryptoObjectType::kPublicKey;

                Inteface.pro.mExportAllowed = obj["Exportable"].GetBool();
                
                std::string SlotType = obj["SlotType"].GetString();
                if( SlotType == "KApplication")
                    Inteface.pro.mSlotType = KeySlotType::kApplication;
                else if( SlotType == "KMachine")
                   Inteface.pro.mSlotType = KeySlotType::kMachine;


                Inteface.pro.mSlotCapacity = obj["slotCapacity"].GetInt();
                Inteface.pro.mAllocateSpareSlot = obj["AllocateShadowCopy"].GetBool();

                int MaxUpdateAllowed = obj["MaxUpdateAllowed"].GetInt();
                if( MaxUpdateAllowed > 0)
                {
                    Inteface.pro.mAllowContentTypeChange = true;
                    Inteface.pro.mMaxUpdateAllowed = obj["MaxUpdateAllowed"].GetInt();
                }
                else
                {
                    Inteface.pro.mAllowContentTypeChange = false;
                    Inteface.pro.mMaxUpdateAllowed = -1;
                }

                KeySlotsMetaData.push_back(Inteface);
            }
        }
    }
    fclose(file);
    return KeySlotsMetaData;    
}

int main()
{
    auto KeySlotsMetaData = parseManifest();

    for (const CryptoKeySlotInterface& Interface : KeySlotsMetaData) 
    {
        std::cout << "InstanceSpecifier: " << Interface.specifier << std::endl;
        std::cout << "CryptoProvider: " << Interface.CryptoProviderName << std::endl;        
        std::cout << "AlgId: " << Interface.pro.mAlgId << std::endl;
        std::cout << "AllowedUsage: " << Interface.pro.mContentAllowedUsage << std::endl;
        
        if(Interface.pro.mObjectType == CryptoObjectType::kPrivateKey)
            std::cout << "Object Type: " << "kPrivateKey" << std::endl;
        else if(Interface.pro.mObjectType == CryptoObjectType::kPublicKey)
            std::cout << "Object Type: " << "kPublicKey" << std::endl;
        
        if(Interface.pro.mExportAllowed)
            std::cout << "Exportable: true" << std::endl;
        else
            std::cout << "Exportable: false" << std::endl;
        
        if(Interface.pro.mSlotType == KeySlotType::kApplication)
            std::cout << "Slot Type: " << "kApplication" << std::endl;
        else if(Interface.pro.mSlotType == KeySlotType::kMachine)
            std::cout << "Slot Type: " << "kMachine" << std::endl;

        std::cout << "--------------------------\n";
    }

    return 0;
}
