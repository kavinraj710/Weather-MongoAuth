using Supabase.Postgrest.Attributes;
using Supabase.Postgrest.Models;
using System.ComponentModel.DataAnnotations;

namespace MongoAuth.Shared.Models
{
    [Table("FavoriteCity")]
    public class FavoriteCity : BaseModel
    {
        [PrimaryKey("idd", true)]
        [Required]
        public Guid idd { get; set; } // Matches int8 in Supabase

        [Column("username")]
        public string username { get; set; } = string.Empty; // User's username



        [Column("description")]
        public string description { get; set; } = string.Empty; // User's role


        [Column("created_at")]
        public DateTime created_at { get; set; } = DateTime.UtcNow; // Creation timestamp
        
        [Column("location")]
        public string location { get; set; } = string.Empty; // User's role

        [Column("role")]
        public string role { get; set; } = "user"; // User's role

    }
}