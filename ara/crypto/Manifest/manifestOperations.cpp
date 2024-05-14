#include "manifestOperations.h"
#include <vector>
#include "CryptoKeySlotInterface.h"
#include <rapidjson/document.h>
#include <rapidjson/filereadstream.h>
#include "../private/common/base_id_types.h"
#include "sharedSlotsInterface.h"
#include <iostream>

namespace ara
{
    namespace crypto
    {
        namespace manifest
        {
            bool parseManifest() 
            {
                FILE* file = fopen("../ara/crypto/Manifest/manifest.json", "r");
                if (file == nullptr)
                {
                    std::cout << "manifest file doesnot exist" << std::endl;
                    return false;
                }

                try 
                {
                    char buffer[65536];
                    rapidjson::FileReadStream is(file, buffer, sizeof(buffer));

                    rapidjson::Document document;
                    document.ParseStream(is);

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
                    return true;
                }
                catch (...) 
                {
                    std::cout << "catching errors in parsing manifest\n";
                    fclose(file);
                    return false;
                }
            }
        }
    }
}