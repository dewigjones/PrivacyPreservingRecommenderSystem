#pragma once
class RecSys{

  int generateMask();
public:
  int UploadRating(int userID, int itemID, int rating);
  int getPredictedRating(int userID, int itemID);
  std::vector<int> getPredictiedRatings(int userID);  
};