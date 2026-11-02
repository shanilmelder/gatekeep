namespace Gatekeep.Kernel.Audit;

public enum ActorKind
{
    System,
    Anonymous,
    Admin,
    User,
    Client,
}

/// <summary>Who caused an event: a kind, plus an internal ID for every kind but the first two.</summary>
public sealed record Actor
{
    public static readonly Actor System = new(ActorKind.System, null);

    public static readonly Actor Anonymous = new(ActorKind.Anonymous, null);

    private Actor(ActorKind kind, Guid? id)
    {
        Kind = kind;
        Id = id;
    }

    public ActorKind Kind { get; }

    public Guid? Id { get; }

    public static Actor Admin(Guid id) => WithId(ActorKind.Admin, id);

    public static Actor User(Guid id) => WithId(ActorKind.User, id);

    public static Actor Client(Guid id) => WithId(ActorKind.Client, id);

    private static Actor WithId(ActorKind kind, Guid id)
    {
        if (id == Guid.Empty)
        {
            throw new ArgumentException("This kind of Actor needs an ID.", nameof(id));
        }

        return new Actor(kind, id);
    }
}
